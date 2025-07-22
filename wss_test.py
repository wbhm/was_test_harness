#!/usr/bin/env python3
"""
WebSocket Endpoint Tester
Tests multiple public WebSocket endpoints using Python websockets and external tools
"""

import asyncio
import websockets
import ssl
import socket
from datetime import datetime
import time
import subprocess
import shutil
import base64
import hashlib
import os
import platform

# List of public WebSocket endpoints to test
ENDPOINTS = [
    "wss://echo.websocket.org",
    "wss://ws.postman-echo.com/raw", 
    "wss://ws.vi-server.org/mirror/",
    "wss://ws.ifelse.io/"
]

def get_timeout_command():
    """
    Get the appropriate timeout command for the current OS
    
    Returns:
        str: timeout command ('timeout' on Linux, 'gtimeout' on macOS if available, None if not available)
    """
    system = platform.system()
    
    if system == "Linux":
        if shutil.which("timeout"):
            return "timeout"
    elif system == "Darwin":  # macOS
        # Try gtimeout first (from coreutils)
        if shutil.which("gtimeout"):
            return "gtimeout"
        elif shutil.which("timeout"):
            return "timeout"
    
    return None

def run_with_timeout(cmd_list, timeout_seconds, **kwargs):
    """
    Run a command with timeout, handling cross-platform differences
    
    Args:
        cmd_list (list): Command as list of strings
        timeout_seconds (int): Timeout in seconds
        **kwargs: Additional arguments for subprocess.run
        
    Returns:
        subprocess.CompletedProcess: Result of subprocess.run
    """
    timeout_cmd = get_timeout_command()
    
    if timeout_cmd:
        # Use system timeout command
        full_cmd = [timeout_cmd, str(timeout_seconds)] + cmd_list
    else:
        # Fall back to subprocess timeout (less reliable for hanging processes)
        full_cmd = cmd_list
        kwargs['timeout'] = timeout_seconds + 2
    
    return subprocess.run(full_cmd, **kwargs)

def diagnose_socat_failure(uri, timeout=10):
    """
    Systematically diagnose why socat failed when Python websockets succeeded
    
    Args:
        uri (str): WebSocket URI to test
        timeout (int): Timeout in seconds
        
    Returns:
        dict: Detailed diagnostic results
    """
    if not shutil.which("socat"):
        return {"available": False, "reason": "socat not installed"}
    
    # Parse URI
    if uri.startswith("wss://"):
        hostname = uri[6:].split('/')[0].split(':')[0]
        port = uri[6:].split('/')[0].split(':')[1] if ':' in uri[6:].split('/')[0] else "443"
        path = '/' + '/'.join(uri[6:].split('/')[1:]) if len(uri[6:].split('/')) > 1 else '/'
        use_ssl = True
    elif uri.startswith("ws://"):
        hostname = uri[5:].split('/')[0].split(':')[0]
        port = uri[5:].split('/')[0].split(':')[1] if ':' in uri[5:].split('/')[0] else "80"
        path = '/' + '/'.join(uri[5:].split('/')[1:]) if len(uri[5:].split('/')) > 1 else '/'
        use_ssl = False
    else:
        return {"available": True, "tests": {}, "diagnosis": "Unsupported URL scheme"}
    
    results = {
        "available": True,
        "hostname": hostname,
        "port": port,
        "path": path,
        "use_ssl": use_ssl,
        "tests": {},
        "diagnosis": "Unknown"
    }
    
    try:
        # Test 1: Basic TCP connectivity (without SSL)
        print(f"    → Testing basic TCP connectivity to {hostname}:{port}")
        result = run_with_timeout(
            ["socat", "-", f"TCP:{hostname}:{port}"], 
            timeout,
            input="", 
            capture_output=True, 
            text=True
        )
        results["tests"]["tcp_connect"] = {
            "success": result.returncode == 0,
            "output": result.stdout[:200],
            "error": result.stderr[:200]
        }
        
        if not results["tests"]["tcp_connect"]["success"]:
            results["diagnosis"] = "Network connectivity issue - TCP connection failed"
            return results
        
        if use_ssl:
            # Test 2: SSL connection with strict validation
            print(f"    → Testing SSL with strict certificate validation")
            result = run_with_timeout(
                ["socat", "-", f"SSL:{hostname}:{port}"], 
                timeout,
                input="", 
                capture_output=True, 
                text=True
            )
            results["tests"]["ssl_strict"] = {
                "success": result.returncode == 0,
                "output": result.stdout[:200],
                "error": result.stderr[:200]
            }
            
            # Test 3: SSL connection with relaxed validation and better compatibility
            print(f"    → Testing SSL with relaxed certificate validation")
            ssl_options = f"SSL:{hostname}:{port},verify=0"
            if platform.system() == "Darwin":  # macOS specific SSL options
                ssl_options += ",method=TLS1.2"
            
            result = run_with_timeout(
                ["socat", "-", ssl_options], 
                timeout,
                input="", 
                capture_output=True, 
                text=True
            )
            results["tests"]["ssl_relaxed"] = {
                "success": result.returncode == 0,
                "output": result.stdout[:200],
                "error": result.stderr[:200]
            }
            
            # Test 4: SSL with SNI and compatibility options
            print(f"    → Testing SSL with Server Name Indication (SNI)")
            ssl_sni_options = f"SSL:{hostname}:{port},verify=0,servername={hostname}"
            if platform.system() == "Darwin":  # macOS
                ssl_sni_options += ",method=TLS1.2"
            
            result = run_with_timeout(
                ["socat", "-", ssl_sni_options], 
                timeout,
                input="", 
                capture_output=True, 
                text=True
            )
            results["tests"]["ssl_sni"] = {
                "success": result.returncode == 0,
                "output": result.stdout[:200],
                "error": result.stderr[:200]
            }
            
            # Determine SSL diagnosis with macOS-specific handling
            if not results["tests"]["ssl_strict"]["success"]:
                if results["tests"]["ssl_relaxed"]["success"]:
                    results["diagnosis"] = "SSL certificate validation issue - server uses invalid/self-signed certificate"
                elif results["tests"]["ssl_sni"]["success"]:
                    results["diagnosis"] = "SSL Server Name Indication (SNI) required"
                elif platform.system() == "Darwin" and "SSL" in results["tests"]["ssl_strict"]["error"]:
                    results["diagnosis"] = "macOS socat SSL compatibility issue - try updating socat or use 'brew install coreutils' for gtimeout"
                else:
                    results["diagnosis"] = "SSL connection issue - cipher suite or protocol version mismatch"
        
        # Test 5: HTTP request (non-WebSocket)
        print(f"    → Testing HTTP request (non-WebSocket)")
        http_request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
        
        if use_ssl:
            ssl_options = f"SSL:{hostname}:{port},verify=0,servername={hostname}"
            if platform.system() == "Darwin":
                ssl_options += ",method=TLS1.2"
            cmd = ["socat", "-", ssl_options]
        else:
            cmd = ["socat", "-", f"TCP:{hostname}:{port}"]
        
        result = run_with_timeout(cmd, timeout, input=http_request, capture_output=True, text=True)
        results["tests"]["http_request"] = {
            "success": result.returncode == 0 and "HTTP/" in result.stdout,
            "status_code": None,
            "output": result.stdout[:500],
            "error": result.stderr[:200]
        }
        
        # Parse HTTP status code
        if results["tests"]["http_request"]["success"] and "HTTP/" in result.stdout:
            try:
                status_line = result.stdout.split('\n')[0]
                results["tests"]["http_request"]["status_code"] = status_line.split()[1]
            except:
                pass
        
        # Test 6: WebSocket handshake
        print(f"    → Testing WebSocket handshake")
        key = base64.b64encode(os.urandom(16)).decode('utf-8')
        ws_request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        
        if use_ssl:
            ssl_options = f"SSL:{hostname}:{port},verify=0,servername={hostname}"
            if platform.system() == "Darwin":
                ssl_options += ",method=TLS1.2"
            cmd = ["socat", "-", ssl_options]
        else:
            cmd = ["socat", "-", f"TCP:{hostname}:{port}"]
            
        result = run_with_timeout(cmd, timeout, input=ws_request, capture_output=True, text=True)
        results["tests"]["websocket_handshake"] = {
            "success": result.returncode == 0 and "101" in result.stdout,
            "output": result.stdout[:500],
            "error": result.stderr[:200]
        }
        
        # Final diagnosis based on all tests
        if use_ssl and results["diagnosis"] != "Unknown":
            pass  # SSL diagnosis already set
        elif results["tests"]["http_request"]["success"]:
            status_code = results["tests"]["http_request"]["status_code"]
            if status_code == "404":
                results["diagnosis"] = "WebSocket endpoint path not found - server responds to HTTP but WebSocket path doesn't exist"
            elif status_code == "405":
                results["diagnosis"] = "Server configuration - endpoint exists but doesn't support WebSocket upgrade"
            elif status_code in ["200", "301", "302"]:
                if not results["tests"]["websocket_handshake"]["success"]:
                    results["diagnosis"] = "WebSocket protocol compliance - server accepts HTTP but rejects WebSocket handshake headers"
                else:
                    results["diagnosis"] = "WebSocket handshake validation - server handshake response doesn't match expected format"
            else:
                results["diagnosis"] = f"HTTP server error - status code {status_code}"
        else:
            results["diagnosis"] = "HTTP protocol issue - server doesn't respond to HTTP requests properly"
            
    except subprocess.TimeoutExpired:
        results["diagnosis"] = "Connection timeout - server too slow to respond"
    except Exception as e:
        results["diagnosis"] = f"Diagnostic error: {str(e)}"
    
    return results

def test_http_with_socat(uri, timeout=10):
    """
    Test basic HTTP connectivity using socat (before WebSocket upgrade)
    
    Args:
        uri (str): WebSocket URI to test
        timeout (int): Timeout in seconds
        
    Returns:
        tuple: (success: bool, message: str, tool_available: bool)
    """
    if not shutil.which("socat"):
        return False, "✗ socat not installed", False
    
    try:
        # Parse URI to get HTTP equivalent
        if uri.startswith("wss://"):
            hostname = uri[6:].split('/')[0].split(':')[0]
            port = uri[6:].split('/')[0].split(':')[1] if ':' in uri[6:].split('/')[0] else "443"
            path = '/' + '/'.join(uri[6:].split('/')[1:]) if len(uri[6:].split('/')) > 1 else '/'
            use_ssl = True
        elif uri.startswith("ws://"):
            hostname = uri[5:].split('/')[0].split(':')[0]
            port = uri[5:].split('/')[0].split(':')[1] if ':' in uri[5:].split('/')[0] else "80"
            path = '/' + '/'.join(uri[5:].split('/')[1:]) if len(uri[5:].split('/')) > 1 else '/'
            use_ssl = False
        else:
            return False, "✗ Unsupported URL scheme", True
            
        # Create simple HTTP GET request (not WebSocket upgrade)
        http_request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\nUser-Agent: socat-http-test\r\n\r\n"
        
        start_time = time.time()
        
        # Setup socat command with cross-platform SSL options
        if use_ssl:
            ssl_options = f"SSL:{hostname}:{port}"
            if platform.system() == "Darwin":  # macOS needs more compatible SSL options
                ssl_options += ",method=TLS1.2,verify=0"
            cmd = ["socat", "-", ssl_options]
        else:
            cmd = ["socat", "-", f"TCP:{hostname}:{port}"]
        
        result = run_with_timeout(
            cmd,
            timeout,
            input=http_request,
            capture_output=True,
            text=True
        )
        
        response_time = time.time() - start_time
        
        if result.returncode == 0:
            response = result.stdout
            
            # Parse HTTP response
            if "HTTP/1.1" in response or "HTTP/1.0" in response:
                status_line = response.split('\n')[0].strip()
                
                if "200 OK" in status_line:
                    return True, f"✓ HTTP connection successful: {status_line} ({response_time:.3f}s)", True
                elif "404" in status_line:
                    return True, f"✓ HTTP connected but endpoint not found: {status_line} ({response_time:.3f}s)", True
                elif "405 Method Not Allowed" in status_line:
                    return True, f"✓ HTTP connected, WebSocket-only endpoint: {status_line} ({response_time:.3f}s)", True
                else:
                    return False, f"✗ HTTP error: {status_line} ({response_time:.3f}s)", True
            else:
                return False, f"✗ No HTTP response received", True
        else:
            error_msg = result.stderr.strip() if result.stderr else "Connection failed"
            return False, f"✗ HTTP connection failed: {error_msg[:100]}", True
            
    except subprocess.TimeoutExpired:
        return False, f"✗ HTTP timeout ({timeout}s)", True
    except Exception as e:
        return False, f"✗ HTTP error: {str(e)}", True

def test_websocket_handshake_with_socat(uri, timeout=10):
    """
    Perform manual WebSocket handshake using socat
    
    Args:
        uri (str): WebSocket URI to test
        timeout (int): Timeout in seconds
        
    Returns:
        tuple: (success: bool, message: str, tool_available: bool)
    """
    if not shutil.which("socat"):
        return False, "✗ socat not installed", False
    
    try:
        # Parse URI
        if uri.startswith("wss://"):
            hostname = uri[6:].split('/')[0].split(':')[0]
            port = uri[6:].split('/')[0].split(':')[1] if ':' in uri[6:].split('/')[0] else "443"
            path = '/' + '/'.join(uri[6:].split('/')[1:]) if len(uri[6:].split('/')) > 1 else '/'
            use_ssl = True
        elif uri.startswith("ws://"):
            hostname = uri[5:].split('/')[0].split(':')[0]
            port = uri[5:].split('/')[0].split(':')[1] if ':' in uri[5:].split('/')[0] else "80"
            path = '/' + '/'.join(uri[5:].split('/')[1:]) if len(uri[5:].split('/')) > 1 else '/'
            use_ssl = False
        else:
            return False, "✗ Unsupported URL scheme", True
            
        # Create WebSocket handshake request
        # Generate WebSocket key
        key = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        # Create HTTP request for WebSocket upgrade
        request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        
        # Expected response key for validation
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        expected_key = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()
        
        start_time = time.time()
        
        # Setup socat command with cross-platform SSL options  
        if use_ssl:
            ssl_options = f"SSL:{hostname}:{port}"
            if platform.system() == "Darwin":  # macOS compatibility
                ssl_options += ",method=TLS1.2,verify=0"
            cmd = ["socat", "-", ssl_options]
        else:
            cmd = ["socat", "-", f"TCP:{hostname}:{port}"]
        
        # Run socat with WebSocket handshake
        result = run_with_timeout(
            cmd,
            timeout,
            input=request,
            capture_output=True,
            text=True
        )
        
        response_time = time.time() - start_time
        
        if result.returncode == 0:
            response = result.stdout
            
            # Check for successful WebSocket handshake
            if "HTTP/1.1 101" in response and "Switching Protocols" in response:
                if f"Sec-WebSocket-Accept: {expected_key}" in response:
                    return True, f"✓ WebSocket handshake successful with key validation ({response_time:.3f}s)", True
                else:
                    return True, f"✓ WebSocket handshake successful but key mismatch ({response_time:.3f}s)", True
            elif "HTTP/1.1" in response:
                status_line = response.split('\n')[0]
                return False, f"✗ WebSocket handshake failed: {status_line.strip()}", True
            else:
                return False, f"✗ No HTTP response received", True
        else:
            error_msg = result.stderr.strip() if result.stderr else "Connection failed"
            return False, f"✗ Connection failed: {error_msg[:100]}", True
            
    except subprocess.TimeoutExpired:
        return False, f"✗ Handshake timeout ({timeout}s)", True
    except Exception as e:
        return False, f"✗ Handshake error: {str(e)}", True

async def test_websocket(uri, timeout=15):
    """
    Test a single WebSocket endpoint using Python websockets
    
    Args:
        uri (str): WebSocket URI to test
        timeout (int): Connection timeout in seconds
        
    Returns:
        tuple: (success: bool, message: str, response_time: float)
    """
    start_time = time.time()
    
    try:
        # Create SSL context that's more permissive for testing
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Attempt to connect with timeout
        async with websockets.connect(
            uri, 
            ssl=ssl_context,
            ping_timeout=timeout,
            ping_interval=None,  # Disable ping/pong for basic testing
            close_timeout=5
        ) as websocket:
            
            response_time = time.time() - start_time
            
            # Try to send a test message and receive response
            try:
                test_message = "test connection"
                await asyncio.wait_for(websocket.send(test_message), timeout=5)
                
                # For echo servers, try to receive the echo
                if any(keyword in uri.lower() for keyword in ["echo", "postman", "vi-server", "ifelse"]):
                    response = await asyncio.wait_for(websocket.recv(), timeout=5)
                    return True, f"✓ Connected successfully (echo received: {response[:50]}...)", response_time
                else:
                    # For data streams, just check if we receive any data
                    try:
                        response = await asyncio.wait_for(websocket.recv(), timeout=3)
                        return True, f"✓ Connected successfully (data received: {len(str(response))} chars)", response_time
                    except asyncio.TimeoutError:
                        # No immediate response is OK for some endpoints
                        return True, "✓ Connected successfully (connection established)", response_time
                        
            except asyncio.TimeoutError:
                return True, "✓ Connected successfully (no echo response - may be data stream)", response_time
            except Exception as msg_error:
                return True, f"✓ Connected but messaging failed: {str(msg_error)}", response_time
                
    except asyncio.TimeoutError:
        response_time = time.time() - start_time
        return False, f"✗ Connection timeout after {timeout} seconds", response_time
        
    except websockets.exceptions.InvalidStatusCode as e:
        response_time = time.time() - start_time
        status_messages = {
            403: "Forbidden - Authentication required or access denied",
            404: "Not Found - WebSocket endpoint doesn't exist",
            503: "Service Unavailable - Server temporarily down/overloaded",
            502: "Bad Gateway - Proxy/load balancer error",
            500: "Internal Server Error - Server-side problem"
        }
        status_msg = status_messages.get(e.status_code, f"HTTP {e.status_code}")
        return False, f"✗ {status_msg}", response_time
        
    except websockets.exceptions.InvalidHandshake as e:
        response_time = time.time() - start_time
        return False, f"✗ WebSocket handshake failed: {str(e)}", response_time
        
    except ssl.SSLError as e:
        response_time = time.time() - start_time
        return False, f"✗ SSL/TLS error: {str(e)}", response_time
        
    except socket.gaierror as e:
        response_time = time.time() - start_time
        return False, f"✗ DNS resolution failed: {str(e)}", response_time
        
    except ConnectionRefusedError:
        response_time = time.time() - start_time
        return False, "✗ Connection refused by server", response_time
        
    except OSError as e:
        response_time = time.time() - start_time
        if "Network is unreachable" in str(e):
            return False, "✗ Network is unreachable", response_time
        elif "Name or service not known" in str(e):
            return False, "✗ DNS resolution failed - hostname not found", response_time
        else:
            return False, f"✗ Network error: {str(e)}", response_time
            
    except Exception as e:
        response_time = time.time() - start_time
        return False, f"✗ Unexpected error: {type(e).__name__}: {str(e)}", response_time

def test_with_external_tool(uri, tool_name, timeout=10):
    """
    Test WebSocket endpoint using external command-line tools
    
    Args:
        uri (str): WebSocket URI to test
        tool_name (str): Tool to use ('wscat', 'websocat', 'socat-http', 'socat-websocket')
        timeout (int): Timeout in seconds
        
    Returns:
        tuple: (success: bool, message: str, tool_available: bool)
    """
    
    # Handle socat variants
    if tool_name == "socat-http":
        return test_http_with_socat(uri, timeout)
    elif tool_name == "socat-websocket":
        return test_websocket_handshake_with_socat(uri, timeout)
    
    # Check if tool is available for other tools
    tool_path = shutil.which(tool_name)
    if not tool_path:
        return False, f"✗ {tool_name} not installed", False
    
    try:
        start_time = time.time()
        
        if tool_name == "wscat":
            # wscat -c URL (connect and exit quickly)
            cmd = ["wscat", "-c", uri, "-w", "2"]  # 2 second wait
        elif tool_name == "websocat":
            # websocat URL with timeout  
            if get_timeout_command():
                cmd = [get_timeout_command(), str(timeout), "websocat", uri]
            else:
                cmd = ["websocat", uri]
        else:
            return False, f"✗ Unsupported tool: {tool_name}", True
            
        # Run the command
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout + 2,
            input="test\n"  # Send test message and newline
        )
        
        response_time = time.time() - start_time
        
        if result.returncode == 0:
            return True, f"✓ WebSocket connection successful ({response_time:.3f}s)", True
        elif result.returncode == 124:  # timeout command exit code
            return False, f"✗ Connection timeout ({timeout}s)", True
        else:
            error_msg = result.stderr.strip() or result.stdout.strip() or "Connection failed"
            return False, f"✗ Failed: {error_msg[:100]}", True
            
    except subprocess.TimeoutExpired:
        return False, f"✗ Process timeout ({timeout}s)", True
    except FileNotFoundError:
        return False, f"✗ {tool_name} command not found", False
    except Exception as e:
        return False, f"✗ Error running {tool_name}: {str(e)}", True

async def test_all_endpoints():
    """Test all WebSocket endpoints using multiple methods"""
    
    print("=" * 80)
    print("WebSocket Endpoint Connectivity Tester (Multi-Tool)")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    print()
    
    # Check which external tools are available
    available_tools = []
    tool_configs = [
        ("wscat", "wscat"),
        ("websocat", "websocat"), 
        ("socat-http", "socat"),
        ("socat-websocket", "socat")
    ]
    
    for tool_name, binary_name in tool_configs:
        if shutil.which(binary_name):
            available_tools.append(tool_name)
    
    if available_tools:
        print(f"External tools available: {', '.join(available_tools)}")
    else:
        print("No external tools found - using Python websockets only")
        print("Install tools:")
        print("  wscat: npm install -g wscat")
        print("  websocat: download binary from GitHub") 
        print("  socat: sudo apt install socat")
    print()
    
    # Add explanatory note about dual socat testing
    if "socat-http" in available_tools or "socat-websocket" in available_tools:
        print("Note: socat tests both HTTP and WebSocket protocols separately")
        print("  socat-http: Basic HTTP connectivity test") 
        print("  socat-websocket: Full WebSocket handshake test")
        print()
    
    results = []
    
    for uri in ENDPOINTS:
        print(f"Testing {uri}")
        print("-" * 50)
        
        # Test with Python websockets
        success, message, response_time = await test_websocket(uri)
        results.append(('Python websockets', uri, success, message, response_time))
        print(f"[Python websockets] {message} ({response_time:.3f}s)")
        
        # Test with external tools
        for tool in available_tools:
            success, message, tool_available = test_with_external_tool(uri, tool)
            if tool_available:
                results.append((tool, uri, success, message, 0))
                print(f"[{tool}] {message}")
                
                # If socat failed but Python succeeded, run detailed diagnosis
                if not success and (tool == "socat-http" or tool == "socat-websocket"):
                    # Check if Python websockets succeeded for this URI
                    python_success = any(r[2] for r in results if r[0] == 'Python websockets' and r[1] == uri)
                    if python_success:
                        print(f"    🔍 Diagnosing socat failure (Python websockets worked)...")
                        diagnosis = diagnose_socat_failure(uri)
                        if diagnosis.get("available", False):
                            print(f"    📋 DIAGNOSIS: {diagnosis['diagnosis']}")
                            
                            # Show key test results
                            tests = diagnosis.get("tests", {})
                            if "ssl_strict" in tests and not tests["ssl_strict"]["success"] and tests.get("ssl_relaxed", {}).get("success", False):
                                print(f"    ├── SSL certificate issue detected")
                            if "http_request" in tests:
                                status = tests["http_request"].get("status_code")
                                if status:
                                    print(f"    ├── HTTP status code: {status}")
                            if "websocket_handshake" in tests and not tests["websocket_handshake"]["success"]:
                                print(f"    └── WebSocket handshake failed")
                        print()
        
        print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    # Group results by tool
    by_tool = {}
    for tool, uri, success, message, response_time in results:
        if tool not in by_tool:
            by_tool[tool] = {'total': 0, 'success': 0, 'results': []}
        by_tool[tool]['total'] += 1
        if success:
            by_tool[tool]['success'] += 1
        by_tool[tool]['results'].append((uri, success, message))
    
    for tool, data in by_tool.items():
        success_rate = (data['success'] / data['total']) * 100
        print(f"\n{tool}:")
        print(f"  Success rate: {data['success']}/{data['total']} ({success_rate:.1f}%)")
        
        # Show failures
        failures = [(uri, msg) for uri, success, msg in data['results'] if not success]
        if failures:
            print("  Failures:")
            for uri, msg in failures:
                print(f"    - {uri}: {msg}")
    
    print(f"\nTest completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """Main function to run the WebSocket tests"""
    try:
        # Check if websockets library is available
        import websockets
    except ImportError:
        print("Error: websockets library not found!")
        print("Install it with one of these methods:")
        print("  1. pip3 install websockets (in virtual environment)")
        print("  2. sudo apt install python3-websockets")
        print("  3. pipx install websockets")
        return 1
    
    try:
        # Run the async test function
        asyncio.run(test_all_endpoints())
        return 0
    except KeyboardInterrupt:
        print("\nTest interrupted by user (Ctrl+C)")
        return 1
    except Exception as e:
        print(f"Unexpected error running tests: {e}")
        return 1

if __name__ == "__main__":
    exit(main())