import asyncio
import json
from datetime import datetime
from aiohttp import web
import aiofiles
import os

# Stockage des clients connectés
connected_clients = set()

# Historique des messages (stocké en mémoire)
message_history = []

async def websocket_handler(request):
    """Gère les connexions WebSocket"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    # Ajouter le client à la liste
    connected_clients.add(ws)
    
    # Envoyer l'historique des messages au nouveau client
    for msg in message_history:
        try:
            await ws.send_json(msg)
        except Exception:
            pass
    
    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    
                    # Créer le message avec timestamp
                    message = {
                        'username': data.get('username', 'Anonyme'),
                        'text': data.get('text', ''),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Ajouter à l'historique (limiter à 1000 messages)
                    message_history.append(message)
                    if len(message_history) > 1000:
                        message_history.pop(0)
                    
                    # Envoyer à tous les clients connectés
                    for client in connected_clients.copy():
                        try:
                            await client.send_json(message)
                        except Exception:
                            connected_clients.discard(client)
                
                except json.JSONDecodeError:
                    pass
            
            elif msg.type == web.WSMsgType.ERROR:
                pass
    
    finally:
        # Retirer le client à la déconnexion
        connected_clients.discard(ws)
    
    return ws


async def index_handler(request):
    """Serve la page HTML du chat"""
    html = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat Local</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .chat-container {
            width: 90%;
            max-width: 600px;
            height: 90vh;
            max-height: 800px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        .chat-header {
            background: #007bff;
            color: white;
            padding: 16px;
            font-size: 18px;
            font-weight: bold;
            border-bottom: 1px solid #0056b3;
        }
        
        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        
        .message {
            display: flex;
            flex-direction: column;
            max-width: 80%;
            word-wrap: break-word;
        }
        
        .message.own {
            align-self: flex-end;
            background: #007bff;
            color: white;
            padding: 10px 14px;
            border-radius: 12px;
            border-bottom-right-radius: 4px;
        }
        
        .message.other {
            align-self: flex-start;
            background: #e9ecef;
            color: #333;
            padding: 10px 14px;
            border-radius: 12px;
            border-bottom-left-radius: 4px;
        }
        
        .message-meta {
            font-size: 12px;
            opacity: 0.7;
            margin-top: 4px;
        }
        
        .message.own .message-meta {
            text-align: right;
        }
        
        .message-username {
            font-weight: bold;
            font-size: 13px;
            margin-bottom: 4px;
        }
        
        .input-area {
            border-top: 1px solid #ddd;
            padding: 12px;
            display: flex;
            gap: 8px;
            background: #fafafa;
        }
        
        .username-input {
            width: 120px;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            font-family: inherit;
        }
        
        .message-input {
            flex: 1;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            font-family: inherit;
            resize: none;
        }
        
        .send-btn {
            background: #007bff;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            transition: background 0.2s;
        }
        
        .send-btn:hover {
            background: #0056b3;
        }
        
        .send-btn:active {
            transform: scale(0.98);
        }
        
        .connection-status {
            position: absolute;
            top: 12px;
            right: 12px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #ccc;
        }
        
        .connection-status.connected {
            background: #28a745;
            box-shadow: 0 0 8px rgba(40, 167, 69, 0.6);
        }
    </style>
</head>
<body>
    <div class="chat-container">
        <div class="chat-header">
            💬 Chat Local
            <div class="connection-status" id="status"></div>
        </div>
        
        <div class="messages" id="messages"></div>
        
        <div class="input-area">
            <input type="text" class="username-input" id="username" placeholder="Ton nom..." maxlength="20" value="Anonyme">
            <input type="text" class="message-input" id="messageInput" placeholder="Écris un message..." />
            <button class="send-btn" id="sendBtn">Envoyer</button>
        </div>
    </div>

    <script>
        const messagesDiv = document.getElementById('messages');
        const messageInput = document.getElementById('messageInput');
        const usernameInput = document.getElementById('username');
        const sendBtn = document.getElementById('sendBtn');
        const statusDiv = document.getElementById('status');
        
        let ws = null;
        let ownUsername = 'Anonyme';
        
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
            
            ws.onopen = () => {
                statusDiv.classList.add('connected');
            };
            
            ws.onmessage = (event) => {
                const message = JSON.parse(event.data);
                displayMessage(message);
            };
            
            ws.onerror = () => {
                statusDiv.classList.remove('connected');
            };
            
            ws.onclose = () => {
                statusDiv.classList.remove('connected');
                setTimeout(connectWebSocket, 3000);
            };
        }
        
        function displayMessage(message) {
            const msgDiv = document.createElement('div');
            const isOwn = message.username === ownUsername;
            msgDiv.className = `message ${isOwn ? 'own' : 'other'}`;
            
            const time = new Date(message.timestamp).toLocaleTimeString('fr-FR');
            
            msgDiv.innerHTML = `
                <div class="message-username">${message.username}</div>
                <div>${message.text}</div>
                <div class="message-meta">${time}</div>
            `;
            
            messagesDiv.appendChild(msgDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        function sendMessage() {
            ownUsername = usernameInput.value.trim() || 'Anonyme';
            const text = messageInput.value.trim();
            
            if (text && ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    username: ownUsername,
                    text: text
                }));
                messageInput.value = '';
                messageInput.focus();
            }
        }
        
        sendBtn.addEventListener('click', sendMessage);
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
        
        usernameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                messageInput.focus();
            }
        });
        
        connectWebSocket();
    </script>
</body>
</html>"""
    return web.Response(text=html, content_type='text/html')


async def start_server(host='0.0.0.0', port=8080):
    """Démarre le serveur"""
    import socket
    
    # Obtenir l'IP locale
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"
    
    app = web.Application()
    app.router.add_get('/', index_handler)
    app.router.add_get('/ws', websocket_handler)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    
    print(f"\n{'='*50}")
    print(f"✓ Serveur de chat démarré!")
    print(f"{'='*50}")
    print(f"Depuis cet ordinateur  : http://localhost:{port}")
    print(f"Depuis le réseau local : http://{local_ip}:{port}")
    print(f"{'='*50}")
    print("Appuie sur Ctrl+C pour arrêter\n")
    
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        print("\n✓ Arrêt du serveur...")
        await runner.cleanup()


if __name__ == '__main__':
    asyncio.run(start_server())
