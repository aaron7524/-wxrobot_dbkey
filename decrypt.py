import os
import sys
import struct
import hmac
import hashlib
import binascii
import argparse
from typing import Tuple

# 第三方加密库 pip install cryptography
try:
    from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("错误: 缺少 'cryptography' 库。请运行: pip install cryptography")
    sys.exit(1)

# 常量定义 (对应 Windows V4 配置)
PAGE_SIZE = 4096
ITER_COUNT = 256000
KEY_SIZE = 32  # 256 bits
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64 # SHA512
BLOCK_SIZE = 16
SQLITE_HEADER = b"SQLite format 3\x00"

class SQLCipherV4Decryptor:
    def __init__(self, key_hex: str):
        self.key = binascii.unhexlify(key_hex)
        if len(self.key) != KEY_SIZE:
            raise ValueError(f"密钥长度错误: 需要 32 字节 (64 hex 字符), 实际 {len(self.key)}")
        
        # 计算 Reserve 大小 (IV + HMAC)，并对齐 AES 块大小
        reserve = IV_SIZE + HMAC_SIZE
        if reserve % BLOCK_SIZE != 0:
            reserve = ((reserve // BLOCK_SIZE) + 1) * BLOCK_SIZE
        self.reserve = reserve

    def _derive_keys(self, salt: bytes) -> Tuple[bytes, bytes]:
        """
        派生加密密钥和 MAC 密钥
        对应 Go 代码中的 deriveKeys
        """
        backend = default_backend()

        # 1. 生成加密密钥 (Encryption Key)
        kdf_enc = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=KEY_SIZE,
            salt=salt,
            iterations=ITER_COUNT,
            backend=backend
        )
        enc_key = kdf_enc.derive(self.key)

        # 2. 生成 MAC 密钥 (MAC Key)
        # 盐值异或 0x3a
        mac_salt = bytes(b ^ 0x3a for b in salt)
        
        kdf_mac = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=KEY_SIZE,
            salt=mac_salt,
            iterations=2, # MAC key 只需要 2 次迭代
            backend=backend
        )
        mac_key = kdf_mac.derive(enc_key)

        return enc_key, mac_key

    def decrypt_file(self, input_path: str, output_path: str):
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"找不到输入文件: {input_path}")

        file_size = os.path.getsize(input_path)
        total_pages = file_size // PAGE_SIZE
        if file_size % PAGE_SIZE != 0:
            total_pages += 1

        print(f"[*] 输入文件: {input_path}")
        print(f"[*] 文件大小: {file_size} bytes")
        print(f"[*] 总页数: {total_pages}")
        print(f"[*] 密钥 (Hex): {binascii.hexlify(self.key).decode()}")

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # 读取第一页的前 16 字节作为 Salt
            # 注意：如果文件小于 PAGE_SIZE，这里会有问题，但数据库通常不为空
            salt = f_in.read(SALT_SIZE)
            if len(salt) != SALT_SIZE:
                raise ValueError("文件太小，无法读取 Salt")
            
            # 检查是否已经是解密文件
            if salt.startswith(b"SQLite format 3"):
                raise ValueError("错误: 文件似乎已经是未加密的 SQLite 数据库。")

            # 重置文件指针回开头
            f_in.seek(0)

            # 派生密钥
            enc_key, mac_key = self._derive_keys(salt)
            print(f"[*] Encryption Key: {binascii.hexlify(enc_key).decode()}")
            print(f"[*] MAC Key: {binascii.hexlify(mac_key).decode()}")

            # 写入标准 SQLite 头 (占位，稍后如果是第1页会写入)
            # 在 Go 代码逻辑中，他是每次解密完一页再写。
            # 这里我们按照 Go 的逻辑：Page 1 特殊处理。
            
            # 必须先写入头部吗？Go代码是先 write(header) 然后处理后续。
            # 但 Go 的 loop 是从 0 开始。
            # 我们按照 Page 循环处理。
            
            # 预先写入 SQLite 头 (为了匹配 Go 代码中的逻辑: output.Write(common.SQLiteHeader))
            # 注意：Go 代码是在打开文件后立即写入头，这是因为它要在解密 Page 1 时跳过前16字节
            f_out.write(SQLITE_HEADER)

            for page_idx in range(total_pages):
                # 读取一页
                page_data = f_in.read(PAGE_SIZE)
                if not page_data:
                    break
                
                # 处理末尾不足一页的情况 (虽然 SQLite 通常对齐)
                if len(page_data) < PAGE_SIZE:
                    # 如果不是满页，直接写入（或者是错误的？）
                    # 通常数据库文件是按页对齐的。这里为了健壮性，简单写入。
                    f_out.write(page_data) 
                    continue

                # 空页检查 (Sparse File Optimization)
                if all(b == 0 for b in page_data):
                    f_out.write(page_data)
                    continue

                try:
                    decrypted_page = self._decrypt_page(
                        page_data, page_idx + 1, enc_key, mac_key
                    )
                    f_out.write(decrypted_page)
                except Exception as e:
                    print(f"\n[!] 第 {page_idx} 页解密失败: {e}")
                    # 失败时可以选择退出或者写入空数据，这里选择抛出
                    raise e

                # 进度条
                if page_idx % 100 == 0:
                    print(f"\r[*] 进度: {page_idx}/{total_pages}", end="")

            print(f"\n[*] 解密完成! 文件已保存至: {output_path}")

    def _decrypt_page(self, page_data: bytes, page_num: int, enc_key: bytes, mac_key: bytes) -> bytes:
        """
        解密单个页面
        """
        # 1. 计算偏移量
        offset = 0
        if page_num == 1:
            offset = SALT_SIZE # 第1页跳过 Salt

        # 2. 提取数据范围
        # Layout: [ ... Data ... | IV (16) | HMAC (64) | ... Padding ... ]
        # The Reserve section is at the end.
        # IV is located at: pageSize - reserve
        # HMAC is located at: pageSize - reserve + IVSize
        
        data_end = PAGE_SIZE - self.reserve + IV_SIZE
        # HMAC 输入: 从 offset 到 data_end (包含 IV)
        hmac_input = page_data[offset:data_end]
        
        # 3. 验证 HMAC
        # Page Number (Little Endian uint32)
        page_num_bytes = struct.pack('<I', page_num)
        
        h = hmac.new(mac_key, digestmod=hashlib.sha512)
        h.update(hmac_input)
        h.update(page_num_bytes)
        calculated_mac = h.digest()

        stored_mac_start = data_end
        stored_mac_end = stored_mac_start + HMAC_SIZE
        stored_mac = page_data[stored_mac_start:stored_mac_end]

        if not hmac.compare_digest(calculated_mac, stored_mac):
             raise ValueError("HMAC 校验失败")

        # 4. 解密
        iv_start = PAGE_SIZE - self.reserve
        iv_end = iv_start + IV_SIZE
        iv = page_data[iv_start:iv_end]

        # 密文区域
        ciphertext_end = PAGE_SIZE - self.reserve
        ciphertext = page_data[offset:ciphertext_end]

        if len(ciphertext) == 0:
            # 可能是极其罕见的情况，比如 Page 1 只有头没有数据？通常不会
            return b''

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # 解密数据保存在 decrypted_data
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # 5. 重组页面
        # 修复了这里的变量名错误: decrypted_page -> decrypted_data
        return decrypted_data + bytes(PAGE_SIZE - len(decrypted_data) - offset)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQLCipher (Windows v4) 解密工具 - Python 版")
    parser.add_argument("-in", "--input", required=True, help="加密的数据库文件路径")
    parser.add_argument("-out", "--output", required=True, help="解密后文件输出路径")
    parser.add_argument("-key", "--key", required=True, help="64位十六进制密钥 (32字节)")

    args = parser.parse_args()

    try:
        decryptor = SQLCipherV4Decryptor(args.key)
        decryptor.decrypt_file(args.input, args.output)
    except Exception as e:
        print(f"\n[X] 错误: {e}")
        sys.exit(1)