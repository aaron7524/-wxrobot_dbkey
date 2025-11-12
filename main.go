package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"echotrace/go_decrypt/internal/decrypt/windows"
)

func main() {
	// 为命令行工具定义参数
	inputPath := flag.String("in", "", "要解密的数据库文件路径 (必需)")
	outputPath := flag.String("out", "", "解密后文件的保存路径 (必需)")
	hexKey := flag.String("key", "", "32字节的十六进制密钥 (必需)")

	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s [选项]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "选项:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// 验证必需的参数
	if *inputPath == "" || *outputPath == "" || *hexKey == "" {
		log.Println("错误: 缺少 -in, -out, 或 -key 参数。")
		flag.Usage()
		os.Exit(1)
	}

	// 验证密钥
	fmt.Println("正在验证密钥...")
	valid, err := validateKey(*inputPath, *hexKey)
	if err != nil {
		log.Fatalf("验证密钥时出错: %v", err)
	}
	if !valid {
		log.Fatalf("错误: 提供的密钥无效。")
	}
	fmt.Println("密钥验证通过。")

	// 执行解密
	fmt.Printf("正在解密文件 %s 到 %s ...\n", *inputPath, *outputPath)
	err = decryptDatabase(*inputPath, *outputPath, *hexKey)
	if err != nil {
		log.Fatalf("解密失败: %v", err)
	}

	fmt.Println("解密成功完成!")
}

// validateKey 验证提供的密钥是否正确
func validateKey(dbPath string, hexKey string) (bool, error) {
	decryptor := windows.NewV4Decryptor()

	// 读取第一页
	file, err := os.Open(dbPath)
	if err != nil {
		return false, fmt.Errorf("无法打开数据库文件: %w", err)
	}
	defer file.Close()

	firstPage := make([]byte, decryptor.GetPageSize())
	_, err = file.Read(firstPage)
	if err != nil {
		return false, fmt.Errorf("无法读取第一页: %w", err)
	}

	// 解码密钥
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return false, fmt.Errorf("无效的十六进制密钥: %w", err)
	}

	// 验证
	return decryptor.Validate(firstPage, keyBytes), nil
}

// decryptDatabase 执行实际的解密操作
func decryptDatabase(inputPath, outputPath, hexKey string) error {
	decryptor := windows.NewV4Decryptor()

	// 创建输出文件
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("无法创建输出文件: %w", err)
	}
	defer outputFile.Close()

	// 执行解密
	ctx := context.Background()
	err = decryptor.Decrypt(ctx, inputPath, hexKey, outputFile)
	if err != nil {
		// 如果解密失败，最好删除不完整的输出文件
		os.Remove(outputPath)
		return fmt.Errorf("解密过程中出错: %w", err)
	}

	return nil
}