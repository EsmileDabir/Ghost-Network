require('dotenv').config();
const express = require("express");
const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http, { 
  cors: { 
    origin: "*",
    methods: ["GET", "POST"]
  } 
});
const path = require("path");
const cron = require("node-cron");
const verifiedCreators = new Set();

// Serve static files from "public"
app.use(express.static("public"));
app.use(express.json());

// Connect to MongoDB Atlas
const mongoose = require("mongoose");
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/college_chat";

mongoose.connect(MONGODB_URI)
.then(() => console.log('✅ Connected to MongoDB Atlas'))
.catch((error) => {
  console.error('❌ MongoDB connection error:', error);
  process.exit(1);
});

// Define Message Schema
const messageSchema = new mongoose.Schema({
  roomId: String,
  name: String,
  message: String,
  timestamp: { type: Date, default: Date.now },
  expiresAt: { type: Date, index: { expireAfterSeconds: 0 } }
});

messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Message = mongoose.model("Message", messageSchema);

// Define Room Schema
const roomSchema = new mongoose.Schema({
  roomId: String,
  name: String,
  createdBy: String,
  createdAt: { type: Date, default: Date.now },
  isGlobal: Boolean,
  isPrivate: { type: Boolean, default: false },
  isHidden: { type: Boolean, default: false },
  users: [{
    socketId: String,
    name: String,
    joinedAt: { type: Date, default: Date.now }
  }],
  pendingJoins: [{
    socketId: String,
    name: String,
    requestedAt: { type: Date, default: Date.now }
  }]
});

const Room = mongoose.model("Room", roomSchema);

// Define Blocked User Schema
const blockedUserSchema = new mongoose.Schema({
  username: String,
  roomId: String,
  blockedBy: String,
  blockedAt: { type: Date, default: Date.now },
  reason: String
});

const BlockedUser = mongoose.model("BlockedUser", blockedUserSchema);

// Define User Activity Schema
const userActivitySchema = new mongoose.Schema({
  username: String,
  roomId: String,
  action: String,
  timestamp: { type: Date, default: Date.now }
});

const UserActivity = mongoose.model('UserActivity', userActivitySchema);

// Store active rooms in memory for real-time updates
const activeRooms = new Map();
const pendingJoinRequests = new Map();
const GLOBAL_ROOM_ID = "global-room";

// Admin controls
const ADMIN_CONTROLS = {
  AUTO_CLEANUP: process.env.AUTO_CLEANUP !== "false",
  ALLOW_ROOM_CREATION: process.env.ALLOW_ROOM_CREATION !== "false",
  MAX_ROOMS: parseInt(process.env.MAX_ROOMS) || 50,
  MAX_USERS_PER_ROOM: parseInt(process.env.MAX_USERS_PER_ROOM) || 100,
  MESSAGE_RATE_LIMIT: parseInt(process.env.MESSAGE_RATE_LIMIT) || 3
};

// Username restrictions
const RESERVED_USERNAMES = ["pain", "admin", "system", "root"];

// Check username availability with creator verification
async function isUsernameAvailable(username, creatorToken = null, socketId = null) {
  try {
    if (socketId && verifiedCreators.has(socketId) && username.toLowerCase() === "pain") {
      return { available: true, isCreator: true };
    }

    if (username.toLowerCase() === "pain") {
      if (creatorToken === process.env.CREATOR_SECRET) {
        if (socketId) {
          verifiedCreators.add(socketId);
          console.log(`✅ Creator verified for socket: ${socketId}`);
        }
        return { available: true, isCreator: true };
      } else {
        return {
          available: false,
          reason: "This username is reserved for the creator",
          requiresCreatorVerification: true
        };
      }
    }

    if (RESERVED_USERNAMES.includes(username.toLowerCase())) {
      return { available: false, reason: "This username is reserved" };
    }

    const rooms = await Room.find({});
    for (const room of rooms) {
      const userExists = room.users.some(user => user.name.toLowerCase() === username.toLowerCase());
      if (userExists) {
        return { available: false, reason: "Username already in use" };
      }
    }

    return { available: true };
  } catch (error) {
    console.error("Error checking username availability:", error);
    return { available: false, reason: "Server error checking username" };
  }
}

// Get filtered room list based on user
async function getFilteredRoomList(username = null) {
  try {
    const rooms = await Room.find({});
    const filteredRooms = rooms.filter(room => {
      if (room.isGlobal) return true;
      if (room.isHidden) {
        return username && (room.createdBy === username || username.toLowerCase() === "pain");
      }
      return true;
    });

    return filteredRooms.map(room => ({
      id: room.roomId,
      name: room.name,
      userCount: room.users.length,
      isGlobal: room.isGlobal,
      isPrivate: room.isPrivate,
      isHidden: room.isHidden,
      createdBy: room.createdBy
    }));
  } catch (error) {
    console.error("Error getting filtered room list:", error);
    return [];
  }
}

// Initialize global room
async function initializeGlobalRoom() {
  try {
    let globalRoom = await Room.findOne({ roomId: GLOBAL_ROOM_ID });

    if (!globalRoom) {
      globalRoom = new Room({
        roomId: GLOBAL_ROOM_ID,
        name: "Global College Chat",
        createdBy: "System",
        isGlobal: true,
        isPrivate: false,
        isHidden: false,
        users: [],
        pendingJoins: []
      });
      await globalRoom.save();
    }

    activeRooms.set(GLOBAL_ROOM_ID, {
      name: globalRoom.name,
      users: new Map(),
      createdAt: globalRoom.createdAt,
      createdBy: globalRoom.createdBy,
      isGlobal: true,
      isPrivate: false,
      isHidden: false
    });

    console.log("Global room initialized");
  } catch (error) {
    console.error("Error initializing global room:", error);
  }
}

// Function to calculate expiration time based on room type
function getExpirationTime(isGlobal = false) {
  const now = new Date();
  if (isGlobal) {
    return new Date(now.getTime() + 48 * 60 * 60 * 1000);
  } else {
    return new Date(now.getTime() + 2 * 60 * 60 * 1000);
  }
}

// Clean up empty private rooms
async function cleanupEmptyRooms() {
  try {
    if (!ADMIN_CONTROLS.AUTO_CLEANUP) return;

    const rooms = await Room.find({ isGlobal: false });
    for (const room of rooms) {
      if (room.users.length === 0) {
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        if (room.updatedAt < oneHourAgo) {
          await Room.deleteOne({ _id: room._id });
          await Message.deleteMany({ roomId: room.roomId });
          activeRooms.delete(room.roomId);
          console.log(`Deleted empty room: ${room.roomId}`);
        }
      }
    }
  } catch (error) {
    console.error("Error cleaning up rooms:", error);
  }
}

// Update room list
async function updateRoomList(username = null) {
  try {
    const roomList = await getFilteredRoomList(username);
    if (username) {
      const sockets = await io.fetchSockets();
      const userSocket = sockets.find(socket => socket.data?.username === username);
      if (userSocket) {
        userSocket.emit("room-update", roomList);
      }
    } else {
      io.emit("room-update", roomList);
    }
  } catch (error) {
    console.error("Error updating room list:", error);
  }
}

// Join room handler with approval system
// Join room handler - SIMPLIFIED (no approval required)
async function joinRoom(socket, { room, name, isCreator, creatorToken, isHidden = false }) {
  try {
    const usernameValidation = await isUsernameAvailable(name, creatorToken, socket.id);
    if (!usernameValidation.available) {
      socket.emit("username-error", { error: usernameValidation.reason });
      return;
    }

    const isBlocked = await BlockedUser.findOne({ username: name, roomId: room });
    if (isBlocked) {
      socket.emit("blocked", { reason: isBlocked.reason });
      socket.disconnect(true);
      return;
    }

    let roomData = await Room.findOne({ roomId: room });

    // Create room if it doesn't exist (except for global room)
    if (!roomData && room !== GLOBAL_ROOM_ID) {
      console.log(`🆕 Creating new private room: ${room} by ${name}`);
      roomData = new Room({
        roomId: room,
        name: `Room ${room}`,
        createdBy: name,
        isGlobal: false,
        isPrivate: true,
        isHidden: isHidden,
        users: [{
          socketId: socket.id,
          name: name,
          joinedAt: new Date()
        }],
        pendingJoins: []
      });
      await roomData.save();
    }

    if (roomData) {
      // Add user to room in database (for both global and private rooms)
      const existingUserIndex = roomData.users.findIndex(user => user.name === name);
      if (existingUserIndex === -1) {
        roomData.users.push({
          socketId: socket.id,
          name: name,
          joinedAt: new Date()
        });
        await roomData.save();
      }

      socket.data.username = name;
      socket.emit("join-success", { room, name });

      // Special welcome for creator
      if (name.toLowerCase() === "pain") {
        console.log(`✅ Creator ${name} joined room ${room}`);
        socket.emit("message", {
          name: "System",
          message: "Welcome, Creator! You have special admin privileges.",
          timestamp: new Date().toLocaleTimeString()
        });
      }

      // Track user activity
      const userActivity = new UserActivity({
        username: name,
        roomId: room,
        action: 'joined'
      });
      await userActivity.save();

      // Update active rooms map
      if (!activeRooms.has(room)) {
        activeRooms.set(room, {
          name: roomData.name,
          users: new Map(),
          createdAt: roomData.createdAt,
          createdBy: roomData.createdBy,
          isGlobal: roomData.isGlobal,
          isPrivate: roomData.isPrivate,
          isHidden: roomData.isHidden
        });
      }

      const activeRoom = activeRooms.get(room);
      activeRoom.users.set(socket.id, name);

      socket.join(room);

      // Send message history to the user
      const messages = await Message.find({ roomId: room }).sort({ timestamp: 1 }).limit(100);
      socket.emit("message-history", messages);

      socket.to(room).emit("message", {
        name: "System",
        message: `Ghost ${name} joined the room`,
        timestamp: new Date().toLocaleTimeString()
      });

      updateRoomList();
      console.log(`Ghost ${name} joined room ${room}`);
    }
  } catch (error) {
    console.error("Error joining room:", error);
  }
}

// Leave room handler
async function leaveRoom(socket, { room, name }) {
  try {
    await Room.updateOne(
      { roomId: room },
      { $pull: { users: { socketId: socket.id } } }
    );
    
    const removedCount = await removeUserMessages(room, name);
    notifyMessageRemoval(room, name);
    
    const userActivity = new UserActivity({
      username: name,
      roomId: room,
      action: 'left'
    });
    await userActivity.save();
    
    if (activeRooms.has(room)) {
      const activeRoom = activeRooms.get(room);
      activeRoom.users.delete(socket.id);
      
      if (activeRoom.users.size === 0 && !activeRoom.isGlobal) {
        activeRooms.delete(room);
      }
    }
    
    socket.to(room).emit("message", { 
      name: "System", 
      message: `Ghost ${name} left the room`,
      timestamp: new Date().toLocaleTimeString()
    });
    
    updateRoomList();
    
    socket.leave(room);
    console.log(`Ghost ${name} left room ${room}, removed ${removedCount} messages`);
    
  } catch (error) {
    console.error("Error in leaveRoom:", error);
  }
}

// Handle disconnect
async function handleDisconnect(socket, reason) {
  console.log(`User disconnected: ${socket.id}, reason: ${reason}`);

  try {
    if (pendingJoinRequests.has(socket.id)) {
      const request = pendingJoinRequests.get(socket.id);
      await Room.updateOne(
        { roomId: request.roomId },
        { $pull: { pendingJoins: { socketId: socket.id } } }
      );
      pendingJoinRequests.delete(socket.id);
    }

    const roomsWithUser = await Room.find({ "users.socketId": socket.id });

    for (const room of roomsWithUser) {
      const user = room.users.find(u => u.socketId === socket.id);

      await Room.updateOne(
        { roomId: room.roomId },
        { $pull: { users: { socketId: socket.id } } }
      );

      if (user) {
        const removedCount = await removeUserMessages(room.roomId, user.name);
        notifyMessageRemoval(room.roomId, user.name);

        const userActivity = new UserActivity({
          username: user.name,
          roomId: room.roomId,
          action: 'left'
        });
        await userActivity.save();
      }

      if (activeRooms.has(room.roomId)) {
        const activeRoom = activeRooms.get(room.roomId);
        activeRoom.users.delete(socket.id);

        if (activeRoom.users.size === 0 && !activeRoom.isGlobal) {
          activeRooms.delete(room.roomId);
        }
      }

      if (user) {
        socket.to(room.roomId).emit("message", {
          name: "System",
          message: `Ghost ${user.name} left the room`,
          timestamp: new Date().toLocaleTimeString()
        });
      }
    }

    updateRoomList();
  } catch (error) {
    console.error("Error handling disconnect:", error);
  }
}

// Remove user messages
async function removeUserMessages(roomId, username) {
  try {
    const result = await Message.deleteMany({ 
      roomId: roomId, 
      name: username 
    });
    console.log(`Removed ${result.deletedCount} messages by ${username} from room ${roomId}`);
    return result.deletedCount;
  } catch (error) {
    console.error("Error removing user messages:", error);
    return 0;
  }
}

// Notify message removal
function notifyMessageRemoval(roomId, username) {
  io.to(roomId).emit("remove-user-messages", { username: username });
  io.to(roomId).emit("message", {
    name: "System",
    message: `All messages by Ghost ${username} have been removed`,
    timestamp: new Date().toLocaleTimeString()
  });
}

// Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/chat", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "chat.html"));
});

app.get("/rooms", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "rooms.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// Test route
app.get("/test", (req, res) => {
  res.json({ message: "Server is running!", timestamp: new Date().toISOString() });
});

// API to get room list
app.get("/rooms-api", async (req, res) => {
  try {
    const { username } = req.query;
    const roomList = await getFilteredRoomList(username);
    res.json(roomList);
  } catch (error) {
    console.error("Error fetching rooms:", error);
    res.status(500).json({ error: "Failed to fetch rooms" });
  }
});

// API to get message history for a room
app.get("/messages/:roomId", async (req, res) => {
  try {
    const { roomId } = req.params;
    const messages = await Message.find({ roomId }).sort({ timestamp: 1 }).limit(100);
    res.json(messages);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// API to check username availability
app.post("/check-username", async (req, res) => {
  try {
    const { username, creatorToken } = req.body;
    const result = await isUsernameAvailable(username, creatorToken);
    res.json(result);
  } catch (error) {
    console.error("Error checking username:", error);
    res.status(500).json({ available: false, reason: "Server error" });
  }
});

// API for creator verification
app.post("/creator-verify", async (req, res) => {
  try {
    const { username, creatorToken } = req.body;

    if (username.toLowerCase() !== "pain") {
      return res.json({ success: false, message: "Not a creator username" });
    }

    if (creatorToken === process.env.CREATOR_SECRET) {
      console.log(`✅ Creator authenticated: ${username}`);
      res.json({ success: true, message: "Creator verified" });
    } else {
      console.log(`🚨 Failed creator attempt: ${username}`);
      res.json({ success: false, message: "Invalid creator token" });
    }
  } catch (error) {
    console.error("Error in creator verification:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ADMIN API ENDPOINTS
app.get("/admin/api/stats", async (req, res) => {
  try {
    const { secret } = req.query;
    
    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const roomCount = await Room.countDocuments();
    const messageCount = await Message.countDocuments();
    const blockedCount = await BlockedUser.countDocuments();
    const activeRoomCount = activeRooms.size;

    const rooms = await Room.find({});
    let totalUsers = 0;
    rooms.forEach(room => {
      totalUsers += room.users.length;
    });

    res.json({
      roomCount,
      totalUsers,
      messageCount,
      blockedCount,
      activeRoomCount,
      activeRooms: Array.from(activeRooms.entries()).map(([id, room]) => ({
        id,
        name: room.name,
        userCount: room.users.size,
        isGlobal: room.isGlobal,
        isPrivate: room.isPrivate
      }))
    });
  } catch (error) {
    console.error("Error fetching stats:", error);
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

app.post("/admin/api/block-user", async (req, res) => {
  try {
    const { username, roomId, reason, secret } = req.body;
    
    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const existingBlock = await BlockedUser.findOne({ username, roomId });
    if (existingBlock) {
      return res.status(400).json({ error: "User already blocked" });
    }

    const blockedUser = new BlockedUser({
      username,
      roomId,
      blockedBy: "Web Admin",
      reason: reason || "Violation of chat rules"
    });

    await blockedUser.save();
    
    const room = activeRooms.get(roomId);
    if (room) {
      for (const [socketId, userName] of room.users.entries()) {
        if (userName === username) {
          io.to(socketId).emit("blocked", { reason });
          io.to(socketId).disconnectSockets(true);
          break;
        }
      }
    }

    res.json({ success: true, message: `User ${username} blocked from room ${roomId}` });
  } catch (error) {
    console.error("Error blocking user:", error);
    res.status(500).json({ error: "Failed to block user" });
  }
});

app.post("/admin/api/delete-room", async (req, res) => {
  try {
    const { roomId, secret } = req.body;
    
    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    if (roomId === GLOBAL_ROOM_ID) {
      return res.status(400).json({ error: "Cannot delete global room" });
    }

    await Room.deleteOne({ roomId });
    await Message.deleteMany({ roomId });
    activeRooms.delete(roomId);

    io.emit("room-deleted", { roomId });

    res.json({ success: true, message: `Room ${roomId} deleted` });
  } catch (error) {
    console.error("Error deleting room:", error);
    res.status(500).json({ error: "Failed to delete room" });
  }
});

app.get("/admin/api/rooms", async (req, res) => {
  try {
    const { secret } = req.query;
    
    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const rooms = await Room.find({});
    const roomList = rooms.map(room => ({
      id: room.roomId,
      name: room.name,
      userCount: room.users.length,
      isGlobal: room.isGlobal,
      isPrivate: room.isPrivate,
      isHidden: room.isHidden,
      createdBy: room.createdBy,
      users: room.users.map(user => user.name)
    }));

    res.json(roomList);
  } catch (error) {
    console.error("Error fetching rooms:", error);
    res.status(500).json({ error: "Failed to fetch rooms" });
  }
});

app.get("/admin/api/blocked-users", async (req, res) => {
  try {
    const { secret } = req.query;
    
    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const blockedUsers = await BlockedUser.find({});
    res.json(blockedUsers);
  } catch (error) {
    console.error("Error fetching blocked users:", error);
    res.status(500).json({ error: "Failed to fetch blocked users" });
  }
});

app.post("/admin/api/unblock-user", async (req, res) => {
  try {
    const { username, roomId, secret } = req.body;
    
    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const result = await BlockedUser.deleteOne({ username, roomId });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: "User not found in block list" });
    }

    res.json({ success: true, message: `User ${username} unblocked from room ${roomId}` });
  } catch (error) {
    console.error("Error unblocking user:", error);
    res.status(500).json({ error: "Failed to unblock user" });
  }
});

// Debug route to check room status
app.get("/debug/room/:roomId", async (req, res) => {
  try {
    const roomId = req.params.roomId;
    const roomData = await Room.findOne({ roomId: roomId });
    const activeRoom = activeRooms.get(roomId);
    
    res.json({
      roomExists: !!roomData,
      roomData: roomData,
      activeRoom: activeRoom ? {
        name: activeRoom.name,
        users: Array.from(activeRoom.users.entries()),
        userCount: activeRoom.users.size
      } : null
    });
  } catch (error) {
    res.json({ error: error.message });
  }
});

// Socket.io connection handling
io.on("connection", (socket) => {
  console.log(`User connected: ${socket.id}`);

  const creatorTokens = {};
  const messageTimestamps = [];

  socket.on("send-message", async (data) => {
    const now = Date.now();
    messageTimestamps.push(now);
    
    while (messageTimestamps.length > 0 && now - messageTimestamps[0] > 1000) {
      messageTimestamps.shift();
    }
    
    if (messageTimestamps.length > ADMIN_CONTROLS.MESSAGE_RATE_LIMIT) {
      socket.emit("message-error", { error: "Message rate limit exceeded" });
      return;
    }
    
    try {
      const { room, name, message } = data;
      
      const isBlocked = await BlockedUser.findOne({ username: name, roomId: room });
      if (isBlocked) {
        socket.emit("blocked", { reason: isBlocked.reason });
        return;
      }
      
      const isGlobal = room === GLOBAL_ROOM_ID;
      const expiresAt = getExpirationTime(isGlobal);
      
      const newMessage = new Message({
        roomId: room,
        name,
        message,
        timestamp: new Date(),
        expiresAt
      });
      
      await newMessage.save();
      
      // ✅ FIX: Broadcast to ALL users in the room
      io.to(room).emit("message", { 
        name: name,
        message: message,
        timestamp: new Date().toLocaleTimeString(),
        isSelf: false
      });
      
      console.log(`📢 Message broadcast to room ${room}: ${name}: ${message}`);
      
    } catch (error) {
      console.error("Error saving message:", error);
    }
  });

  // Handle join request approvals
  // socket.on("approve-join-request", async (data) => {
  //   try {
  //     const { requestSocketId, roomId } = data;
      
  //     const roomData = await Room.findOne({ roomId: roomId });
  //     if (!roomData) {
  //       socket.emit("request-error", { error: "Room not found" });
  //       return;
  //     }

  //     const isAdmin = roomData.users.some(user => 
  //       user.socketId === socket.id && 
  //       (user.name === roomData.createdBy || user.name.toLowerCase() === "pain")
  //     );

  //     if (!isAdmin) {
  //       socket.emit("request-error", { error: "Only room admins can approve join requests" });
  //       return;
  //     }

  //     const requestIndex = roomData.pendingJoins.findIndex(req => req.socketId === requestSocketId);
  //     if (requestIndex === -1) {
  //       socket.emit("request-error", { error: "Join request not found" });
  //       return;
  //     }

  //     const request = roomData.pendingJoins[requestIndex];
      
  //     roomData.users.push({
  //       socketId: request.socketId,
  //       name: request.name,
  //       joinedAt: new Date()
  //     });
      
  //     roomData.pendingJoins.splice(requestIndex, 1);
  //     await roomData.save();

  //     pendingJoinRequests.delete(requestSocketId);

  //     io.to(requestSocketId).emit("join-approved", { 
  //       room: roomId, 
  //       name: request.name 
  //     });

  //     io.to(roomId).emit("message", {
  //       name: "System",
  //       message: `Ghost ${request.name} joined the room`,
  //       timestamp: new Date().toLocaleTimeString()
  //     });

  //     updateRoomList();

  //     console.log(`Join request approved for ${request.name} in room ${roomId}`);
  //   } catch (error) {
  //     console.error("Error approving join request:", error);
  //     socket.emit("request-error", { error: "Failed to approve join request" });
  //   }
  // });

  // Handle join request rejections
  // socket.on("reject-join-request", async (data) => {
  //   try {
  //     const { requestSocketId, roomId } = data;
      
  //     const roomData = await Room.findOne({ roomId: roomId });
  //     if (!roomData) {
  //       socket.emit("request-error", { error: "Room not found" });
  //       return;
  //     }

  //     const isAdmin = roomData.users.some(user => 
  //       user.socketId === socket.id && 
  //       (user.name === roomData.createdBy || user.name.toLowerCase() === "pain")
  //     );

  //     if (!isAdmin) {
  //       socket.emit("request-error", { error: "Only room admins can reject join requests" });
  //       return;
  //     }

  //     const requestIndex = roomData.pendingJoins.findIndex(req => req.socketId === requestSocketId);
  //     if (requestIndex === -1) {
  //       socket.emit("request-error", { error: "Join request not found" });
  //       return;
  //     }

  //     const request = roomData.pendingJoins[requestIndex];
      
  //     roomData.pendingJoins.splice(requestIndex, 1);
  //     await roomData.save();

  //     pendingJoinRequests.delete(requestSocketId);

  //     io.to(requestSocketId).emit("join-rejected", { 
  //       room: roomId, 
  //       reason: "Your join request was rejected by the room admin" 
  //     });

  //     console.log(`Join request rejected for ${request.name} in room ${roomId}`);
  //   } catch (error) {
  //     console.error("Error rejecting join request:", error);
  //     socket.emit("request-error", { error: "Failed to reject join request" });
  //   }
  // });

  socket.on("join-room", async (data) => {
    if (data.creatorToken) {
      creatorTokens[socket.id] = data.creatorToken;
    }
    await joinRoom(socket, {
      ...data,
      creatorToken: creatorTokens[socket.id]
    });
  });

  socket.on("leave-room", async (data) => await leaveRoom(socket, data));
  
  socket.on("disconnect", async (reason) => {
    delete creatorTokens[socket.id];
    await handleDisconnect(socket, reason);
  });
});

// Schedule cleanup jobs
cron.schedule('0 * * * *', cleanupEmptyRooms);

cron.schedule('0 * * * *', async () => {
  try {
    const now = new Date();
    const result = await Message.deleteMany({
      expiresAt: { $lt: now }
    });

    if (result.deletedCount > 0) {
      console.log(`Cleaned up ${result.deletedCount} expired messages`);
    }
  } catch (error) {
    console.error('Error cleaning up expired messages:', error);
  }
});

// Initialize server
const PORT = process.env.PORT || 3001;

async function startServer() {
  try {
    await initializeGlobalRoom();

    http.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🌐 Test URL: http://localhost:${PORT}/test`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();