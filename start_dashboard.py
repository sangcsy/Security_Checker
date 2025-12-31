"""
Simple HTTP Server for Security Dashboard
"""
import http.server
import socketserver
import webbrowser
import os
import sys

PORT = 8080

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Expires', '0')
        super().end_headers()
    
    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

def start_server():
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    print("=" * 80)
    print("🌐 Windows 보안 검사 대시보드 서버")
    print("=" * 80)
    print()
    
    # Check required files
    required_files = [
        'dashboard.html',
        'dashboard.css',
        'dashboard.js',
        'check_definitions.json'
    ]
    
    missing = [f for f in required_files if not os.path.exists(f)]
    if missing:
        print("❌ 다음 파일이 없습니다:")
        for f in missing:
            print(f"   - {f}")
        print()
        sys.exit(1)
    
    print("✓ 모든 필수 파일 확인 완료")
    print(f"✓ 포트 {PORT} 사용")
    print()
    
    url = f"http://localhost:{PORT}/"
    print(f"📍 서버 주소: {url}")
    print(f"📁 서버 경로: {script_dir}")
    print()
    print("대시보드 사용 방법:")
    print("1. 브라우저가 자동으로 열립니다")
    print("2. '검사 결과 파일 선택' 버튼을 클릭하세요")
    print("3. JSON 결과 파일을 선택하세요")
    print()
    print("⚠️  서버를 종료하려면 Ctrl+C를 누르세요")
    print()
    print("-" * 80)
    print()
    
    # Start server
    Handler = MyHTTPRequestHandler
    
    try:
        with socketserver.TCPServer(("", PORT), Handler) as httpd:
            print(f"✓ 서버가 시작되었습니다!")
            print()
            print("서버 로그:")
            print()
            
            # Open browser
            webbrowser.open(url)
            
            # Serve forever
            httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        print("🛑 서버 종료 중...")
        print()
    except OSError as e:
        if e.errno == 10048:  # Port already in use
            print(f"❌ 포트 {PORT}는 이미 사용 중입니다.")
            print("다른 포트를 사용하거나 해당 포트를 사용 중인 프로그램을 종료하세요.")
        else:
            print(f"❌ 서버 오류: {e}")
    finally:
        print("✓ 서버가 종료되었습니다.")
        print()

if __name__ == "__main__":
    start_server()
