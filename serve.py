#!/usr/bin/env python3
"""
RISC-V CVE Visualization Dashboard - Static File Server
简单的HTTP服务器用于本地测试和演示
"""

import os
import sys
import http.server
import socketserver
import webbrowser
from pathlib import Path

# 配置
DEFAULT_PORT = 3657
VISUALIZATION_DIR = Path(__file__).parent.absolute()

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """自定义HTTP请求处理器"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(VISUALIZATION_DIR), **kwargs)
    
    def guess_type(self, path):
        """改进MIME类型猜测"""
        result = super().guess_type(path)
        
        # 修复JSON文件的MIME类型
        if path.endswith('.json'):
            return 'application/json'
        
        return result
    
    def end_headers(self):
        """添加CORS头部"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

def find_available_port(start_port=DEFAULT_PORT):
    """查找可用端口"""
    import socket
    
    for port in range(start_port, start_port + 10):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                return port
        except OSError:
            continue
    return None

def check_data_files():
    """检查必要的数据文件是否存在"""
    required_files = [
        '../riscv_cves_classified.json',
        '../riscv_cves_classified_summary.json'
    ]
    
    missing_files = []
    for file_path in required_files:
        full_path = VISUALIZATION_DIR / file_path
        if not full_path.exists():
            missing_files.append(file_path)
    
    if missing_files:
        print("❌ 缺少必要的数据文件:")
        for file in missing_files:
            print(f"   {file}")
        print("\n请确保已运行CVE分类分析脚本生成这些文件。")
        return False
    
    print("✅ 数据文件检查通过")
    return True

def main():
    """主函数"""
    print("RISC-V CVE 可视化仪表板")
    print("=" * 40)
    
    # 检查数据文件
    if not check_data_files():
        sys.exit(1)
    
    # 解析命令行参数
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"❌ 无效的端口号: {sys.argv[1]}")
            sys.exit(1)
    
    # 查找可用端口
    available_port = find_available_port(port)
    if available_port is None:
        print(f"❌ 无法找到可用端口 (尝试了 {port}-{port+9})")
        sys.exit(1)
    
    if available_port != port:
        print(f"⚠️  端口 {port} 不可用，使用端口 {available_port}")
    
    # 启动服务器
    try:
        with socketserver.TCPServer(("0.0.0.0", available_port), CustomHTTPRequestHandler) as httpd:
            server_url = f"http://localhost:{available_port}"
            
            print(f"🚀 服务器启动成功!")
            print(f"📁 根目录: {VISUALIZATION_DIR}")
            print(f"🌐 本地访问: {server_url}")
            print(f"🌐 远程访问: http://<your-ip>:{available_port}")
            print(f"⏹️  按 Ctrl+C 停止服务器")
            print()
            
            # 自动打开浏览器
            try:
                webbrowser.open(server_url)
                print("🔗 已在默认浏览器中打开")
            except Exception:
                print("📋 请手动在浏览器中打开上述地址")
            
            print()
            print("服务器日志:")
            print("-" * 40)
            
            # 运行服务器
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n\n👋 服务器已停止")
    except Exception as e:
        print(f"❌ 服务器启动失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()