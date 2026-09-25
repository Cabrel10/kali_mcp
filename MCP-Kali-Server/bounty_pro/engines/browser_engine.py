"""
Human Browser Engine - Advanced Browser Automation
===================================================
Goes beyond basic Playwright with human-like behavior:
- Natural mouse movements with Bezier curves
- Character-by-character typing with variable delays
- Natural scrolling patterns
- Multi-tab management
- WebSocket interception
- Storage manipulation (IndexedDB, LocalStorage, SessionStorage)
- Shadow DOM traversal
- Service Worker interception
- File upload/download
- Drag & drop
- Canvas/WebGL inspection
- WebRTC leak detection
- Clipboard manipulation
"""

import asyncio
import random
import math
import time
import json
import base64
from typing import Dict, Any, Optional, List, Tuple, Callable
from dataclasses import dataclass, field


# ============================================================================
# HUMAN BEHAVIOR SIMULATION
# ============================================================================

class HumanBehavior:
    """Simulates human-like interaction patterns"""
    
    @staticmethod
    def bezier_curve(start: Tuple[float, float], end: Tuple[float, float], 
                    steps: int = 20) -> List[Tuple[float, float]]:
        """Generate mouse movement path using Bezier curves"""
        # Random control points for natural curve
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        
        # Two control points for cubic Bezier
        cp1 = (
            start[0] + dx * random.uniform(0.2, 0.4) + random.uniform(-50, 50),
            start[1] + dy * random.uniform(0.1, 0.3) + random.uniform(-30, 30)
        )
        cp2 = (
            start[0] + dx * random.uniform(0.6, 0.8) + random.uniform(-50, 50),
            start[1] + dy * random.uniform(0.7, 0.9) + random.uniform(-30, 30)
        )
        
        points = []
        for i in range(steps + 1):
            t = i / steps
            # Cubic Bezier formula
            x = (1-t)**3 * start[0] + 3*(1-t)**2*t * cp1[0] + 3*(1-t)*t**2 * cp2[0] + t**3 * end[0]
            y = (1-t)**3 * start[1] + 3*(1-t)**2*t * cp1[1] + 3*(1-t)*t**2 * cp2[1] + t**3 * end[1]
            points.append((int(x), int(y)))
        
        return points
    
    @staticmethod
    def typing_delays(text: str) -> List[float]:
        """Generate human-like typing delays"""
        delays = []
        for i, char in enumerate(text):
            # Base delay
            delay = random.gauss(0.08, 0.03)
            
            # Longer delay after punctuation
            if char in '.!?':
                delay += random.uniform(0.2, 0.5)
            elif char in ',;:':
                delay += random.uniform(0.1, 0.2)
            elif char == ' ':
                delay += random.uniform(0.02, 0.08)
            
            # Occasional "thinking" pause
            if random.random() < 0.02:
                delay += random.uniform(0.5, 1.5)
            
            # Occasional typo and correction
            # (handled in the browser engine)
            
            delays.append(max(0.02, delay))
        
        return delays
    
    @staticmethod
    def scroll_pattern(total_distance: int, viewport_height: int) -> List[Dict]:
        """Generate natural scrolling pattern"""
        scrolls = []
        current = 0
        
        while current < total_distance:
            # Variable scroll distance
            scroll_amount = random.randint(
                int(viewport_height * 0.3), 
                int(viewport_height * 0.8)
            )
            
            # Sometimes scroll up slightly (reading back)
            if random.random() < 0.1 and current > viewport_height:
                scroll_amount = -random.randint(50, 200)
            
            current += scroll_amount
            
            # Variable pause between scrolls
            pause = random.uniform(0.5, 3.0)
            if random.random() < 0.15:
                pause += random.uniform(2, 8)  # Longer reading pause
            
            scrolls.append({
                "delta": scroll_amount,
                "pause": pause,
                "position": current
            })
        
        return scrolls
    
    @staticmethod
    def random_viewport() -> Dict:
        """Generate a realistic viewport size"""
        viewports = [
            {"width": 1920, "height": 1080},
            {"width": 1366, "height": 768},
            {"width": 1440, "height": 900},
            {"width": 1536, "height": 864},
            {"width": 1280, "height": 720},
            {"width": 2560, "height": 1440},
        ]
        return random.choice(viewports)


# ============================================================================
# BROWSER ENGINE
# ============================================================================

class HumanBrowserEngine:
    """
    Advanced browser automation engine with human-like behavior.
    Wraps Playwright with additional capabilities.
    """
    
    def __init__(self):
        self.pages: Dict[str, Any] = {}  # tab_id -> page
        self.browser = None
        self.context = None
        self.intercepted_ws: List[Dict] = []
        self.intercepted_requests: List[Dict] = []
        self.storage_data: Dict[str, Any] = {}
        self.current_mouse_pos = (0, 0)
        self.behavior = HumanBehavior()
    
    async def launch(self, headless: bool = True, proxy: str = None,
                    fingerprint: Dict = None) -> Dict:
        """Launch browser with anti-detection measures"""
        try:
            from playwright.async_api import async_playwright
            
            self._pw = await async_playwright().start()
            
            launch_args = [
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-first-run',
                '--disable-gpu',
            ]
            
            browser_kwargs = {
                "headless": headless,
                "args": launch_args,
            }
            
            if proxy:
                browser_kwargs["proxy"] = {"server": proxy}
            
            self.browser = await self._pw.chromium.launch(**browser_kwargs)
            
            # Create context with anti-detection
            viewport = fingerprint.get("viewport", self.behavior.random_viewport()) if fingerprint else self.behavior.random_viewport()
            
            context_kwargs = {
                "viewport": viewport,
                "user_agent": fingerprint.get("user_agent", self._random_user_agent()) if fingerprint else self._random_user_agent(),
                "locale": "en-US",
                "timezone_id": "America/New_York",
                "permissions": ["geolocation"],
            }
            
            self.context = await self.browser.new_context(**context_kwargs)
            
            # Anti-detection scripts
            await self.context.add_init_script("""
                // Remove webdriver flag
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                
                // Fake plugins
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5]
                });
                
                // Fake languages
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en']
                });
                
                // Override permissions
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                    Promise.resolve({ state: Notification.permission }) :
                    originalQuery(parameters)
                );
                
                // Chrome runtime
                window.chrome = { runtime: {} };
                
                // Fake screen dimensions
                Object.defineProperty(screen, 'colorDepth', {get: () => 24});
            """)
            
            return {"status": "launched", "viewport": viewport}
            
        except ImportError:
            return {"error": "Playwright not installed. Run: pip install playwright && playwright install"}
        except Exception as e:
            return {"error": str(e)}
    
    async def new_tab(self, url: str = "", tab_id: str = None) -> str:
        """Open a new tab"""
        if not self.context:
            return ""
        
        tab_id = tab_id or f"tab_{len(self.pages)}"
        page = await self.context.new_page()
        
        # Set up request interception
        page.on("request", lambda req: self._on_request(req, tab_id))
        page.on("websocket", lambda ws: self._on_websocket(ws, tab_id))
        
        if url:
            await page.goto(url, wait_until="networkidle", timeout=30000)
        
        self.pages[tab_id] = page
        return tab_id
    
    async def human_navigate(self, tab_id: str, url: str) -> Dict:
        """Navigate with human-like behavior (random delay before)"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        # Random pre-navigation delay
        await asyncio.sleep(random.uniform(0.3, 1.5))
        
        response = await page.goto(url, wait_until="networkidle", timeout=30000)
        
        # Random post-navigation delay (reading)
        await asyncio.sleep(random.uniform(0.5, 2.0))
        
        return {
            "url": page.url,
            "status": response.status if response else 0,
            "title": await page.title()
        }
    
    async def human_click(self, tab_id: str, selector: str) -> Dict:
        """Click with human-like mouse movement"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            element = await page.wait_for_selector(selector, timeout=10000)
            if not element:
                return {"error": "Element not found"}
            
            # Get element position
            box = await element.bounding_box()
            if not box:
                return {"error": "Element not visible"}
            
            # Target position (with slight randomness)
            target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
            target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)
            
            # Move mouse along Bezier curve
            path = self.behavior.bezier_curve(
                self.current_mouse_pos,
                (target_x, target_y),
                steps=random.randint(15, 30)
            )
            
            for point in path:
                await page.mouse.move(point[0], point[1])
                await asyncio.sleep(random.uniform(0.005, 0.02))
            
            # Small pause before clicking
            await asyncio.sleep(random.uniform(0.05, 0.15))
            
            # Click with random hold time
            await page.mouse.down()
            await asyncio.sleep(random.uniform(0.05, 0.12))
            await page.mouse.up()
            
            self.current_mouse_pos = (target_x, target_y)
            
            return {"clicked": selector, "position": {"x": target_x, "y": target_y}}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def human_type(self, tab_id: str, selector: str, text: str,
                        clear_first: bool = True) -> Dict:
        """Type with human-like character-by-character delays"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            # Click the input first
            await self.human_click(tab_id, selector)
            await asyncio.sleep(random.uniform(0.1, 0.3))
            
            if clear_first:
                # Select all and delete
                await page.keyboard.press("Control+A")
                await asyncio.sleep(random.uniform(0.05, 0.1))
                await page.keyboard.press("Backspace")
                await asyncio.sleep(random.uniform(0.1, 0.2))
            
            # Type character by character
            delays = self.behavior.typing_delays(text)
            typos_made = 0
            
            for i, (char, delay) in enumerate(zip(text, delays)):
                # Simulate occasional typo (2% chance)
                if random.random() < 0.02 and i > 0:
                    # Type wrong char
                    wrong_char = chr(ord(char) + random.choice([-1, 1]))
                    await page.keyboard.type(wrong_char)
                    await asyncio.sleep(random.uniform(0.1, 0.3))
                    # Delete it
                    await page.keyboard.press("Backspace")
                    await asyncio.sleep(random.uniform(0.05, 0.15))
                    typos_made += 1
                
                await page.keyboard.type(char)
                await asyncio.sleep(delay)
            
            return {"typed": text, "length": len(text), "typos_corrected": typos_made}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def human_scroll(self, tab_id: str, distance: int = 1000) -> Dict:
        """Scroll with natural patterns"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        viewport = page.viewport_size
        viewport_height = viewport["height"] if viewport else 768
        
        pattern = self.behavior.scroll_pattern(distance, viewport_height)
        
        for scroll in pattern:
            await page.mouse.wheel(0, scroll["delta"])
            await asyncio.sleep(scroll["pause"])
        
        return {"scrolled": distance, "steps": len(pattern)}
    
    async def drag_drop(self, tab_id: str, source_selector: str, 
                       target_selector: str) -> Dict:
        """Perform drag and drop"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            source = await page.wait_for_selector(source_selector)
            target = await page.wait_for_selector(target_selector)
            
            source_box = await source.bounding_box()
            target_box = await target.bounding_box()
            
            if not source_box or not target_box:
                return {"error": "Elements not visible"}
            
            # Move to source
            sx = source_box["x"] + source_box["width"] / 2
            sy = source_box["y"] + source_box["height"] / 2
            tx = target_box["x"] + target_box["width"] / 2
            ty = target_box["y"] + target_box["height"] / 2
            
            await page.mouse.move(sx, sy)
            await asyncio.sleep(random.uniform(0.1, 0.2))
            await page.mouse.down()
            await asyncio.sleep(random.uniform(0.1, 0.3))
            
            # Move along path
            path = self.behavior.bezier_curve((sx, sy), (tx, ty), steps=20)
            for point in path:
                await page.mouse.move(point[0], point[1])
                await asyncio.sleep(0.02)
            
            await asyncio.sleep(random.uniform(0.05, 0.1))
            await page.mouse.up()
            
            return {"dragged": source_selector, "dropped_on": target_selector}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def upload_file(self, tab_id: str, selector: str, 
                         file_path: str) -> Dict:
        """Upload a file to a file input"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            input_element = await page.wait_for_selector(selector)
            await input_element.set_input_files(file_path)
            return {"uploaded": file_path, "selector": selector}
        except Exception as e:
            return {"error": str(e)}
    
    async def intercept_websocket(self, tab_id: str) -> List[Dict]:
        """Get intercepted WebSocket messages"""
        return [msg for msg in self.intercepted_ws if msg.get("tab") == tab_id]
    
    async def get_storage(self, tab_id: str, storage_type: str = "localStorage") -> Dict:
        """Get browser storage contents"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            if storage_type == "localStorage":
                data = await page.evaluate("() => Object.fromEntries(Object.entries(localStorage))")
            elif storage_type == "sessionStorage":
                data = await page.evaluate("() => Object.fromEntries(Object.entries(sessionStorage))")
            elif storage_type == "indexedDB":
                data = await page.evaluate("""
                    async () => {
                        const dbs = await indexedDB.databases();
                        return dbs.map(db => ({name: db.name, version: db.version}));
                    }
                """)
            elif storage_type == "cookies":
                cookies = await self.context.cookies()
                data = cookies
            else:
                data = {}
            
            return {"type": storage_type, "data": data}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def set_storage(self, tab_id: str, key: str, value: str,
                         storage_type: str = "localStorage") -> Dict:
        """Modify browser storage"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            if storage_type == "localStorage":
                await page.evaluate(f"localStorage.setItem('{key}', '{value}')")
            elif storage_type == "sessionStorage":
                await page.evaluate(f"sessionStorage.setItem('{key}', '{value}')")
            
            return {"set": key, "value": value, "storage": storage_type}
        except Exception as e:
            return {"error": str(e)}
    
    async def get_shadow_dom(self, tab_id: str, host_selector: str) -> Dict:
        """Access Shadow DOM content"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            content = await page.evaluate(f"""
                () => {{
                    const host = document.querySelector('{host_selector}');
                    if (!host || !host.shadowRoot) return null;
                    return {{
                        innerHTML: host.shadowRoot.innerHTML,
                        childCount: host.shadowRoot.children.length,
                        styles: host.shadowRoot.querySelector('style')?.textContent || ''
                    }};
                }}
            """)
            return {"shadow_dom": content}
        except Exception as e:
            return {"error": str(e)}
    
    async def inspect_canvas(self, tab_id: str, selector: str = "canvas") -> Dict:
        """Extract canvas content"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            data_url = await page.evaluate(f"""
                () => {{
                    const canvas = document.querySelector('{selector}');
                    if (!canvas) return null;
                    return {{
                        width: canvas.width,
                        height: canvas.height,
                        dataUrl: canvas.toDataURL('image/png').substring(0, 100),
                        context: canvas.getContext('2d') ? '2d' : 
                                 canvas.getContext('webgl') ? 'webgl' : 'unknown'
                    }};
                }}
            """)
            return {"canvas": data_url}
        except Exception as e:
            return {"error": str(e)}
    
    async def check_webrtc_leaks(self, tab_id: str) -> Dict:
        """Check for WebRTC IP leaks"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            ips = await page.evaluate("""
                () => new Promise((resolve) => {
                    const ips = [];
                    const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
                    pc.createDataChannel('');
                    pc.createOffer().then(offer => pc.setLocalDescription(offer));
                    pc.onicecandidate = (e) => {
                        if (!e.candidate) {
                            resolve(ips);
                            return;
                        }
                        const parts = e.candidate.candidate.split(' ');
                        const ip = parts[4];
                        if (ip && !ips.includes(ip)) ips.push(ip);
                    };
                    setTimeout(() => resolve(ips), 3000);
                })
            """)
            return {"webrtc_ips": ips, "leak_detected": len(ips) > 0}
        except Exception as e:
            return {"error": str(e)}
    
    async def get_service_workers(self, tab_id: str) -> Dict:
        """List registered service workers"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            workers = await page.evaluate("""
                async () => {
                    const registrations = await navigator.serviceWorker.getRegistrations();
                    return registrations.map(r => ({
                        scope: r.scope,
                        active: r.active ? r.active.scriptURL : null,
                        waiting: r.waiting ? r.waiting.scriptURL : null
                    }));
                }
            """)
            return {"service_workers": workers}
        except Exception as e:
            return {"error": str(e)}
    
    async def extract_page_data(self, tab_id: str) -> Dict:
        """Extract comprehensive page data for security analysis"""
        page = self.pages.get(tab_id)
        if not page:
            return {"error": "Tab not found"}
        
        try:
            data = await page.evaluate("""
                () => ({
                    url: window.location.href,
                    title: document.title,
                    cookies: document.cookie,
                    localStorage: Object.fromEntries(Object.entries(localStorage)),
                    sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
                    forms: Array.from(document.forms).map(f => ({
                        action: f.action,
                        method: f.method,
                        inputs: Array.from(f.elements).map(e => ({
                            name: e.name, type: e.type, value: e.value
                        }))
                    })),
                    links: Array.from(document.links).map(l => l.href).slice(0, 100),
                    scripts: Array.from(document.scripts).map(s => s.src || s.textContent.substring(0, 200)),
                    meta: Array.from(document.querySelectorAll('meta')).map(m => ({
                        name: m.name || m.getAttribute('property'),
                        content: m.content
                    })),
                    iframes: Array.from(document.querySelectorAll('iframe')).map(i => ({
                        src: i.src, sandbox: i.sandbox?.value
                    })),
                    headers_from_meta: {
                        csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content,
                        xfo: document.querySelector('meta[http-equiv="X-Frame-Options"]')?.content
                    }
                })
            """)
            return data
        except Exception as e:
            return {"error": str(e)}
    
    async def close(self) -> None:
        """Close the browser"""
        if self.browser:
            await self.browser.close()
        if hasattr(self, '_pw') and self._pw:
            await self._pw.stop()
    
    def _on_request(self, request, tab_id: str) -> None:
        """Callback for intercepted requests"""
        self.intercepted_requests.append({
            "tab": tab_id,
            "url": request.url,
            "method": request.method,
            "headers": request.headers,
            "post_data": request.post_data,
            "timestamp": time.time()
        })
    
    def _on_websocket(self, ws, tab_id: str) -> None:
        """Callback for WebSocket connections"""
        self.intercepted_ws.append({
            "tab": tab_id,
            "url": ws.url,
            "timestamp": time.time(),
            "messages": []
        })
        
        ws.on("framereceived", lambda data: self.intercepted_ws[-1]["messages"].append({
            "direction": "received", "data": data, "time": time.time()
        }))
        ws.on("framesent", lambda data: self.intercepted_ws[-1]["messages"].append({
            "direction": "sent", "data": data, "time": time.time()
        }))
    
    def _random_user_agent(self) -> str:
        """Generate a random realistic user agent"""
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ]
        return random.choice(agents)
