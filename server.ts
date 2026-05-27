import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure persistent database path
const DB_FILE = path.join(__dirname, 'database.json');

// Interface structures
interface User {
  id: string;
  username: string; // original spelling/casing
  usernameLower: string; // lowercase for unique checks
  displayName: string;
  passwordHash: string;
  createdAt: number;
}

interface Message {
  id: string;
  senderId: string;
  receiverId: string;
  text: string;
  timestamp: number;
  mediaType?: 'image' | 'video' | 'audio';
  mediaUrl?: string;
}

interface DatabaseSchema {
  users: { [userId: string]: User };
  usernames: { [usernameLower: string]: string }; // usernameLower -> userId
  friends: { [userId: string]: string[] }; // userId -> Array of friend userIds
  messages: Message[];
}

// Initial dummy database state if not present
const initialDb: DatabaseSchema = {
  users: {},
  usernames: {},
  friends: {},
  messages: [],
};

// Database utility functions
function readDb(): DatabaseSchema {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, 'utf-8');
      return JSON.parse(raw);
    }
  } catch (err) {
    console.error('Failed to read database file, resetting to initial state', err);
  }
  return initialDb;
}

function writeDb(data: DatabaseSchema) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to write database file', err);
  }
}

// Ensure database file exists
if (!fs.existsSync(DB_FILE)) {
  writeDb(initialDb);
}

// Session tokens (In-Memory for security and rapid retrieval)
// tokenId -> userId
const sessions = new Map<string, string>();

function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex');
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ limit: '50mb', extended: true }));

  // Ensure uploads directory exists on startup
  const UPLOADS_DIR = path.join(__dirname, 'uploads');
  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }
  app.use('/uploads', express.static(UPLOADS_DIR));

  // Connected SSE clients mapping: userId -> active responses array
  const activeClients = new Map<string, express.Response[]>();

  // Broadcaster helper for real-time messaging
  function sendRealtimeEvent(targetUserId: string, payload: any) {
    const clients = activeClients.get(targetUserId);
    if (clients && clients.length > 0) {
      const dataStr = `data: ${JSON.stringify(payload)}\n\n`;
      clients.forEach(res => {
        try {
          res.write(dataStr);
        } catch (e) {
          console.error(`Error writing event to user ${targetUserId}`, e);
        }
      });
    }
  }

  // Auth Middleware
  function authenticate(req: express.Request, res: express.Response, next: express.NextFunction) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Unauthorized: Missing bearer token' });
      return;
    }
    const token = authHeader.substring(7);
    const userId = sessions.get(token);
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized: Session expired or invalid' });
      return;
    }
    const dbData = readDb();
    const user = dbData.users[userId];
    if (!user) {
      res.status(401).json({ error: 'Unauthorized: User not found' });
      return;
    }
    // Attach user to request
    (req as any).user = user;
    next();
  }

  // --- API Authentication Endpoints ---

  // Register
  app.post('/api/auth/register', (req, res) => {
    const { username, password, displayName } = req.body;

    if (!username || typeof username !== 'string' || username.trim().length === 0) {
      res.status(400).json({ error: 'Username is required and must be a valid string' });
      return;
    }
    if (!password || typeof password !== 'string' || password.length < 4) {
      res.status(400).json({ error: 'Password must be at least 4 characters long' });
      return;
    }

    let cleanUsername = username.trim();
    while (cleanUsername.startsWith('@')) {
      cleanUsername = cleanUsername.substring(1).trim();
    }
    const usernameLower = cleanUsername.toLowerCase();
    const finalDisplayName = (displayName && typeof displayName === 'string' && displayName.trim().length > 0)
      ? displayName.trim()
      : cleanUsername;

    // String size limits to avoid DDOS profile poisoning
    if (cleanUsername.length > 24) {
      res.status(400).json({ error: 'Username must not exceed 24 characters' });
      return;
    }
    if (cleanUsername.length < 2) {
      res.status(400).json({ error: 'Username must be at least 2 characters long' });
      return;
    }
    if (finalDisplayName.length > 32) {
      res.status(400).json({ error: 'Display name must not exceed 32 characters' });
      return;
    }

    const dbData = readDb();

    if (dbData.usernames[usernameLower]) {
      res.status(400).json({ error: 'Username is already taken' });
      return;
    }

    const userId = 'u_' + crypto.randomUUID();
    const newUser: User = {
      id: userId,
      username: cleanUsername,
      usernameLower,
      displayName: finalDisplayName,
      passwordHash: hashPassword(password),
      createdAt: Date.now(),
    };

    dbData.users[userId] = newUser;
    dbData.usernames[usernameLower] = userId;
    dbData.friends[userId] = []; // Initialize friendships array

    writeDb(dbData);

    // Create session on signup
    const token = 'token_' + crypto.randomBytes(32).toString('hex');
    sessions.set(token, userId);

    const { passwordHash, ...userPayload } = newUser;
    res.status(201).json({ token, user: userPayload });
  });

  // Login
  app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      res.status(400).json({ error: 'Both username and password are required' });
      return;
    }

    let rawUsername = String(username).trim();
    while (rawUsername.startsWith('@')) {
      rawUsername = rawUsername.substring(1).trim();
    }
    const usernameLower = rawUsername.toLowerCase();
    const dbData = readDb();
    const userId = dbData.usernames[usernameLower];

    if (!userId) {
      res.status(401).json({ error: '@' + rawUsername + ' is not registered yet. Switch to the "Register" tab at the top to create your account!' });
      return;
    }

    const user = dbData.users[userId];
    if (user.passwordHash !== hashPassword(password)) {
      res.status(401).json({ error: 'Incorrect password for @' + user.username + '. Please try again.' });
      return;
    }

    // Create active token session
    const token = 'token_' + crypto.randomBytes(32).toString('hex');
    sessions.set(token, userId);

    const { passwordHash, ...userPayload } = user;
    res.json({ token, user: userPayload });
  });

  // Fetch Current User Profiler
  app.get('/api/users/me', authenticate, (req: any, res) => {
    const { passwordHash, ...userPayload } = req.user;
    res.json({ user: userPayload });
  });

  // Update Current User profile details
  app.post('/api/users/update', authenticate, (req: any, res) => {
    const { displayName, customTheme, avatarGradient } = req.body;
    const currentUser = req.user as any;

    if (displayName !== undefined) {
      if (typeof displayName !== 'string' || displayName.trim().length === 0) {
        res.status(400).json({ error: 'Display name must be a valid string' });
        return;
      }
      if (displayName.length > 32) {
        res.status(400).json({ error: 'Display name must not exceed 32 characters' });
        return;
      }
      currentUser.displayName = displayName.trim();
    }

    if (customTheme !== undefined) {
      currentUser.customTheme = customTheme;
    }
    if (avatarGradient !== undefined) {
      currentUser.avatarGradient = avatarGradient;
    }
    if (req.body.statusText !== undefined) {
      currentUser.statusText = String(req.body.statusText).substring(0, 80);
    }

    const dbData = readDb();
    dbData.users[currentUser.id] = currentUser;
    writeDb(dbData);

    // Notify friends that this user has updated their profile details
    const userFriends = dbData.friends[currentUser.id] || [];
    userFriends.forEach((friendId) => {
      sendRealtimeEvent(friendId, {
        type: 'friend_updated',
        user: {
          id: currentUser.id,
          username: currentUser.username,
          displayName: currentUser.displayName,
          statusText: currentUser.statusText || '',
          avatarGradient: currentUser.avatarGradient || 'liquid_sapphire'
        }
      });
    });

    const { passwordHash, ...userPayload } = currentUser;
    res.json({ success: true, user: userPayload });
  });

  // --- Real-time Chat Streaming EventSource Endpoint ---

  app.get('/api/chats/stream', (req, res) => {
    const token = req.query.token as string;
    if (!token) {
      res.status(401).send('Token parameter is required for the real-time stream.');
      return;
    }

    const userId = sessions.get(token);
    if (!userId) {
      res.status(401).send('Session invalid or expired.');
      return;
    }

    // Standard Server-Sent Events headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no', // Disable buffering for Nginx and proxies
    });

    // Send visual heartbeat
    res.write('retry: 5000\n');
    res.write('data: {"connected": true}\n\n');

    // Add current response socket to active users map
    if (!activeClients.has(userId)) {
      activeClients.set(userId, []);
    }
    activeClients.get(userId)!.push(res);

    // Keep connection alive with simple pings
    const pingInterval = setInterval(() => {
      try {
        res.write('data: {"ping": true}\n\n');
      } catch (e) {
        clearInterval(pingInterval);
      }
    }, 15000);

    req.on('close', () => {
      clearInterval(pingInterval);
      const list = activeClients.get(userId) || [];
      activeClients.set(userId, list.filter(activeRes => activeRes !== res));
      if (activeClients.get(userId)!.length === 0) {
        activeClients.delete(userId);
      }
    });
  });

  // --- Friendship Routing ---

  // Add friend by typed Username
  app.post('/api/friends/add', authenticate, (req: any, res) => {
    const { username } = req.body;
    const currentUser = req.user as User;

    if (!username || typeof username !== 'string' || username.trim().length === 0) {
      res.status(400).json({ error: 'Friend username is required' });
      return;
    }

    let cleanFriendName = username.trim();
    while (cleanFriendName.startsWith('@')) {
      cleanFriendName = cleanFriendName.substring(1).trim();
    }
    const friendUsernameLower = cleanFriendName.toLowerCase();

    if (friendUsernameLower === currentUser.usernameLower) {
      res.status(400).json({ error: 'You cannot add yourself as a friend' });
      return;
    }

    const dbData = readDb();
    const friendId = dbData.usernames[friendUsernameLower];

    if (!friendId) {
      res.status(404).json({ error: `User "@${cleanFriendName}" does not exist. Check the spelling or case and try again.` });
      return;
    }

    // Check existing friends list
    const userFriends = dbData.friends[currentUser.id] || [];
    if (userFriends.includes(friendId)) {
      res.status(400).json({ error: 'You are already friends with this user' });
      return;
    }

    // Bidirectional friendship logic
    const currentFriendsList = dbData.friends[currentUser.id] || [];
    currentFriendsList.push(friendId);
    dbData.friends[currentUser.id] = currentFriendsList;

    const targetFriendsList = dbData.friends[friendId] || [];
    if (!targetFriendsList.includes(currentUser.id)) {
      targetFriendsList.push(currentUser.id);
      dbData.friends[friendId] = targetFriendsList;
    }

    writeDb(dbData);

    const friendUserObj = dbData.users[friendId];

    // Notify the added user via real-time stream that they have a new friend
    sendRealtimeEvent(friendId, {
      type: 'friend_added',
      friend: {
        id: currentUser.id,
        username: currentUser.username,
        displayName: currentUser.displayName,
      }
    });

    res.json({
      success: true,
      friend: {
        id: friendUserObj.id,
        username: friendUserObj.username,
        displayName: friendUserObj.displayName,
      }
    });
  });

  // Fetch Friends List
  app.get('/api/friends/list', authenticate, (req: any, res) => {
    const currentUser = req.user as User;
    const dbData = readDb();
    const friendsIds = dbData.friends[currentUser.id] || [];

    const list = friendsIds.map(fid => {
      const u = dbData.users[fid] as any;
      return {
        id: u.id,
        username: u.username,
        displayName: u.displayName,
        isOnline: activeClients.has(u.id),
        statusText: u.statusText || '',
        avatarGradient: u.avatarGradient || 'liquid_sapphire',
      };
    });

    res.json(list);
  });

  // --- Chatting & Message Thread API ---

  // Get conversation history with helper details
  app.get('/api/chats/:friendId/messages', authenticate, (req: any, res) => {
    const currentUser = req.user as User;
    const { friendId } = req.params;
    const dbData = readDb();

    // Verify friendship exists before allowing message fetch
    const friendsIds = dbData.friends[currentUser.id] || [];
    if (!friendsIds.includes(friendId)) {
      res.status(403).json({ error: 'You can only view messages with friends' });
      return;
    }

    const filtered = dbData.messages.filter(msg => {
      return (
        (msg.senderId === currentUser.id && msg.receiverId === friendId) ||
        (msg.senderId === friendId && msg.receiverId === currentUser.id)
      );
    });

    res.json(filtered);
  });

  // Send Direct Message
  app.post('/api/chats/:friendId/messages', authenticate, (req: any, res) => {
    const currentUser = req.user as User;
    const { friendId } = req.params;
    const { text, mediaType, mediaUrl } = req.body;

    if ((!text || typeof text !== 'string' || text.trim().length === 0) && !mediaUrl) {
      res.status(400).json({ error: 'Message content or a media file attachment must be specified' });
      return;
    }

    if (text && text.length > 2000) {
      res.status(400).json({ error: 'Message character limit is 2000' });
      return;
    }

    const dbData = readDb();

    // Verify friendship exists before allowing delivery
    const friendsIds = dbData.friends[currentUser.id] || [];
    if (!friendsIds.includes(friendId)) {
      res.status(403).json({ error: 'You must add this user as a friend first before sending messages' });
      return;
    }

    const messageId = 'msg_' + crypto.randomUUID();
    const newMessage: Message = {
      id: messageId,
      senderId: currentUser.id,
      receiverId: friendId,
      text: (text || '').trim(),
      timestamp: Date.now(),
      mediaType,
      mediaUrl,
    };

    dbData.messages.push(newMessage);
    writeDb(dbData);

    // Push real-time events to both sender and receiver to instantly append the bubble
    sendRealtimeEvent(friendId, {
      type: 'message_incoming',
      message: newMessage,
    });

    sendRealtimeEvent(currentUser.id, {
      type: 'message_incoming',
      message: newMessage,
    });

    res.status(201).json(newMessage);
  });

  // Upload attachments (images, video, music/audio) as base64 payload
  app.post('/api/uploads', authenticate, (req: any, res) => {
    const { filename, fileType, base64 } = req.body;
    if (!filename || !fileType || !base64) {
      res.status(400).json({ error: 'Filename, fileType, and base64 encoded string are required.' });
      return;
    }

    try {
      const buffer = Buffer.from(base64, 'base64');
      const ext = path.extname(filename) || '.bin';
      const secureName = 'up_' + crypto.randomUUID() + ext;
      const targetPath = path.join(path.join(__dirname, 'uploads'), secureName);

      fs.writeFileSync(targetPath, buffer);
      const mediaUrl = `/uploads/${secureName}`;
      res.json({ success: true, mediaUrl });
    } catch (err: any) {
      console.error('Core file write error:', err);
      res.status(500).json({ error: 'Failed to write uploaded media file to storage disk' });
    }
  });

  // Delete message
  app.delete('/api/chats/messages/:messageId', authenticate, (req: any, res) => {
    const currentUser = req.user as User;
    const { messageId } = req.params;
    const dbData = readDb();

    const msgIndex = dbData.messages.findIndex(m => m.id === messageId);
    if (msgIndex === -1) {
      res.status(404).json({ error: 'Message not found' });
      return;
    }

    const msg = dbData.messages[msgIndex];
    if (msg.senderId !== currentUser.id) {
      res.status(403).json({ error: 'You are only permitted to delete your own sent messages.' });
      return;
    }

    // Remove message completely
    dbData.messages.splice(msgIndex, 1);
    writeDb(dbData);

    // Notify both sender & receiver stream clients to erase bubble instantly
    sendRealtimeEvent(msg.receiverId, {
      type: 'message_deleted',
      messageId: msg.id
    });

    sendRealtimeEvent(currentUser.id, {
      type: 'message_deleted',
      messageId: msg.id
    });

    res.json({ success: true, messageId });
  });

  // --- Serve Client Side Web Application ---

  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, 'dist')));
    // Single page routing fall-through
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  } else {
    // Integrate Vite Server dynamically
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  const port = 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log(`Port: 3000 online. Server operational.`);
  });
}

startServer().catch(err => {
  console.error('Core app crashing at initial boot sequence:', err);
});
