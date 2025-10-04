require('dotenv').config();
console.log("Environment check:");
console.log("MONGODB_URI:", process.env.MONGODB_URI ? "Set" : "Not set");
console.log("PORT:", process.env.PORT);
console.log("NODE_ENV:", process.env.NODE_ENV);
const express = require("express");
const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http, { 
  cors: { 
    origin: process.env.NODE_ENV === "production" 
      ? ["https://your-domain.com", "http://localhost:3000"] 
      : "*",
    methods: ["GET", "POST"]
  } 
});
const path = require("path");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");

const cron = require("node-cron");
const readline = require("readline");
const verifiedCreators = new Set();

// Security middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Logging middleware
app.use(morgan('combined'));

// HTTPS redirect for production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }
  next();
});

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

// Handle connection events
mongoose.connection.on('connected', () => {
  console.log('Mongoose connected to MongoDB Atlas');
});

mongoose.connection.on('error', (err) => {
  console.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose disconnected from MongoDB Atlas');
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
  isHidden: { type: Boolean, default: false }, // New field for hidden rooms
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
  action: String, // 'joined' or 'left'
  timestamp: { type: Date, default: Date.now }
});

const UserActivity = mongoose.model('UserActivity', userActivitySchema);

// Store active rooms in memory for real-time updates
const activeRooms = new Map();

// Store pending join requests
const pendingJoinRequests = new Map();

// Global room ID
const GLOBAL_ROOM_ID = "global-room";

// Admin controls
const ADMIN_CONTROLS = {
  AUTO_CLEANUP: process.env.AUTO_CLEANUP !== "false",
  ALLOW_ROOM_CREATION: process.env.ALLOW_ROOM_CREATION !== "false",
  MAX_ROOMS: parseInt(process.env.MAX_ROOMS) || 50,
  MAX_USERS_PER_ROOM: parseInt(process.env.MAX_USERS_PER_ROOM) || 100,
  MESSAGE_RATE_LIMIT: parseInt(process.env.MESSAGE_RATE_LIMIT) || 3
};

// Admin verification questions and answers
const adminQuestions = [
  "What was the name of your 2nd crush?",
  "Your role model?",
  "Are you introvert or extrovert?"
];

const adminAnswers = [
  "siyakakkar",
  "last prophet",
  "i am kira"
];

// Username restrictions
const RESERVED_USERNAMES = ["pain", "admin", "system", "root"];
const CREATOR_USERNAME = "pain";

// Add this function to check username availability with creator verification
async function isUsernameAvailable(username, creatorToken = null, socketId = null) {
  try {
    // Check if this socket is already verified as creator
    if (socketId && verifiedCreators.has(socketId) && username.toLowerCase() === "pain") {
      return { available: true, isCreator: true };
    }

    // Special case: if username is "pain", check if it's the creator
    if (username.toLowerCase() === "pain") {
      // Use process.env.CREATOR_SECRET directly
      if (creatorToken === process.env.CREATOR_SECRET) {
        // Add to verified creators if socketId is provided
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

    // Check if username is reserved
    if (RESERVED_USERNAMES.includes(username.toLowerCase())) {
      return { available: false, reason: "This username is reserved" };
    }

    // Check if username is already in use in any room
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

// Helper function to get filtered room list based on user
async function getFilteredRoomList(username = null) {
  try {
    const rooms = await Room.find({});
    const filteredRooms = rooms.filter(room => {
      // Always show global room
      if (room.isGlobal) return true;
      
      // Show hidden rooms only to creator or admin
      if (room.isHidden) {
        return username && (room.createdBy === username || username.toLowerCase() === "pain");
      }
      
      // Show non-hidden rooms to everyone
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

// Process message with rate limiting
async function processMessage(socket, { room, name, message }) {
  try {
    // Check if user is blocked from this room
    const isBlocked = await BlockedUser.findOne({ username: name, roomId: room });
    if (isBlocked) {
      socket.emit("blocked", { reason: isBlocked.reason });
      return;
    }

    // Save message to database with appropriate expiration
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

    io.to(room).emit("message", {
      name,
      message,
      timestamp: new Date().toLocaleTimeString()
    });
  } catch (error) {
    console.error("Error saving message:", error);
  }
}

// Helper function to update room list
async function updateRoomList(username = null) {
  try {
    const roomList = await getFilteredRoomList(username);
    if (username) {
      // Send personalized room list to specific user
      const userSocket = Array.from(io.sockets.sockets.values())
        .find(socket => socket.data?.username === username);
      if (userSocket) {
        userSocket.emit("room-update", roomList);
      }
    } else {
      // Broadcast to all users (for cases where we don't have specific user)
      io.emit("room-update", roomList);
    }
  } catch (error) {
    console.error("Error updating room list:", error);
  }
}

// Join room handler with approval system
async function joinRoom(socket, { room, name, isCreator, creatorToken, isHidden = false }) {
  try {
    // Validate username first - WITH CREATOR TOKEN SUPPORT
    const usernameValidation = await isUsernameAvailable(name, creatorToken, socket.id);
    if (!usernameValidation.available) {
      socket.emit("username-error", { error: usernameValidation.reason });

      // Special handling for creator name attempt
      if (name.toLowerCase() === "pain") {
        console.log(`🚨 Creator login failed for: ${name}, token: ${creatorToken}`);
      }

      return;
    }

    // Check if user is blocked from this room
    const isBlocked = await BlockedUser.findOne({ username: name, roomId: room });
    if (isBlocked) {
      socket.emit("blocked", { reason: isBlocked.reason });
      socket.disconnect(true);
      return;
    }

    // Check if room exists in database
    let roomData = await Room.findOne({ roomId: room });

    // Create room if it doesn't exist (except for global room)
    if (!roomData && room !== GLOBAL_ROOM_ID) {
      roomData = new Room({
        roomId: room,
        name: `Room ${room}`,
        createdBy: isCreator ? name : 'Unknown',
        isGlobal: false,
        isPrivate: true, // New rooms are private by default
        isHidden: isHidden, // Set hidden flag
        users: [],
        pendingJoins: []
      });
      await roomData.save();
    }

    if (roomData) {
      // Handle global room - no approval needed
      if (roomData.isGlobal) {
        // Add user to room in database
        roomData.users.push({
          socketId: socket.id,
          name: name,
          joinedAt: new Date()
        });
        await roomData.save();

        // Store username in socket data
        socket.data.username = name;

        socket.emit("join-success", { room, name });

        // Special welcome for creator
        if (name.toLowerCase() === "pain") {
          console.log(`✅ Creator ${name} successfully joined room ${room}`);
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

        // Update all clients with new room user count
        updateRoomList();

        console.log(`Ghost ${name} joined room ${room}`);
        return;
      }

      // Handle private room - require approval
      if (roomData.isPrivate) {
        // Check if user is already in the room
        const existingUser = roomData.users.find(user => user.name === name);
        if (existingUser) {
          socket.data.username = name;
          socket.emit("join-success", { room, name });
          socket.join(room);
          console.log(`Ghost ${name} reconnected to private room ${room}`);
          return;
        }

        // Check if user already has a pending request
        const existingRequest = roomData.pendingJoins.find(req => req.name === name);
        if (existingRequest) {
          socket.emit("join-pending", { message: "Your join request is pending approval" });
          return;
        }

        // Add join request
        roomData.pendingJoins.push({
          socketId: socket.id,
          name: name,
          requestedAt: new Date()
        });
        await roomData.save();

        // Store request in memory for quick access
        pendingJoinRequests.set(socket.id, {
          roomId: room,
          name: name,
          requestedAt: new Date()
        });

        // Notify room admin(s) about the join request
        const adminUsers = roomData.users.filter(user => 
          user.name === roomData.createdBy || user.name.toLowerCase() === "pain"
        );

        adminUsers.forEach(admin => {
          io.to(admin.socketId).emit("join-request", {
            socketId: socket.id,
            name: name,
            roomId: room,
            roomName: roomData.name,
            requestedAt: new Date()
          });
        });

        socket.emit("join-pending", { 
          message: "Join request sent to room admin for approval" 
        });

        console.log(`Join request from ${name} to room ${room}`);
        return;
      }

      // Handle non-private rooms (existing logic)
      roomData.users.push({
        socketId: socket.id,
        name: name,
        joinedAt: new Date()
      });
      await roomData.save();

      // Store username in socket data
      socket.data.username = name;

      socket.emit("join-success", { room, name });

      // Special welcome for creator
      if (name.toLowerCase() === "pain") {
        console.log(`✅ Creator ${name} successfully joined room ${room}`);
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

      // Update all clients with new room user count
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
    // 1. Remove user from room in database
    await Room.updateOne(
      { roomId: room },
      { $pull: { users: { socketId: socket.id } } }
    );
    
    // 2. Remove ALL user messages from database
    const removedCount = await removeUserMessages(room, name);
    
    // 3. Notify all clients to remove messages from UI
    notifyMessageRemoval(room, name);
    
    // 4. Track user activity
    const userActivity = new UserActivity({
      username: name,
      roomId: room,
      action: 'left'
    });
    await userActivity.save();
    
    // 5. Update active rooms
    if (activeRooms.has(room)) {
      const activeRoom = activeRooms.get(room);
      activeRoom.users.delete(socket.id);
      
      if (activeRoom.users.size === 0 && !activeRoom.isGlobal) {
        activeRooms.delete(room);
      }
    }
    
    // 6. Notify room about user leaving
    socket.to(room).emit("message", { 
      name: "System", 
      message: `Ghost ${name} left the room`,
      timestamp: new Date().toLocaleTimeString()
    });
    
    // 7. Update room list for all clients
    updateRoomList();
    
    socket.leave(room);
    console.log(`Ghost ${name} left room ${room}, removed ${removedCount} messages`);
    
  } catch (error) {
    console.error("Error in leaveRoom:", error);
  }
}

// Verify admin handler
function verifyAdmin({ answers }, callback) {
  let verified = true;
  for (let i = 0; i < adminAnswers.length; i++) {
    if (answers[i].toLowerCase() !== adminAnswers[i].toLowerCase()) {
      verified = false;
      break;
    }
  }

  callback({ verified });
}

// Handle disconnect
async function handleDisconnect(socket, reason) {
  console.log(`User disconnected: ${socket.id}, reason: ${reason}`);

  try {
    // Remove any pending join requests
    if (pendingJoinRequests.has(socket.id)) {
      const request = pendingJoinRequests.get(socket.id);
      await Room.updateOne(
        { roomId: request.roomId },
        { $pull: { pendingJoins: { socketId: socket.id } } }
      );
      pendingJoinRequests.delete(socket.id);
    }

    // Find and remove user from all rooms in database
    const roomsWithUser = await Room.find({ "users.socketId": socket.id });

    for (const room of roomsWithUser) {
      // Find the user before removing them
      const user = room.users.find(u => u.socketId === socket.id);

      await Room.updateOne(
        { roomId: room.roomId },
        { $pull: { users: { socketId: socket.id } } }
      );

      // REMOVE USER MESSAGES ON DISCONNECT
      if (user) {
        const removedCount = await removeUserMessages(room.roomId, user.name);
        notifyMessageRemoval(room.roomId, user.name);

        // Track user activity
        const userActivity = new UserActivity({
          username: user.name,
          roomId: room.roomId,
          action: 'left'
        });
        await userActivity.save();
      }

      // Update active rooms
      if (activeRooms.has(room.roomId)) {
        const activeRoom = activeRooms.get(room.roomId);
        activeRoom.users.delete(socket.id);

        // Remove room from active rooms if empty and not global
        if (activeRoom.users.size === 0 && !activeRoom.isGlobal) {
          activeRooms.delete(room.roomId);
        }
      }

      // Notify room about user leaving
      if (user) {
        socket.to(room.roomId).emit("message", {
          name: "System",
          message: `Ghost ${user.name} left the room`,
          timestamp: new Date().toLocaleTimeString()
        });
      }
    }

    // Update room list for all clients
    updateRoomList();
  } catch (error) {
    console.error("Error handling disconnect:", error);
  }
}

// Set up admin command line interface
function setupAdminCLI() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'ADMIN> '
  });

  console.log('Admin CLI activated. Type "help" for commands.');

  rl.prompt();

  rl.on('line', async (line) => {
    const [command, ...args] = line.trim().split(' ');

    try {
      switch (command) {
        case 'help':
          console.log(`
Admin Commands:
  help                          - Show this help
  stats                         - Show server statistics
  list-rooms                    - List all rooms
  list-blocked [roomId]         - List blocked users (optionally for a room)
  block <username> <roomId> [reason] - Block a user from a room
  unblock <username> <roomId>   - Unblock a user from a room
  remove-user <username> <roomId> - Remove user from a room
  kick-user <username> <roomId> - Immediately kick user from room
  delete-room <roomId>          - Delete a room
  cleanup-users                 - Remove inactive users from all rooms
  user-activity [username] [roomId] [limit] - Show user activity
  room-users <roomId>           - Show users in a specific room
  active-users                  - Show currently active users
  debug-rooms                   - Debug room information
  pending-requests <roomId>     - Show pending join requests for a room
  create-hidden-room <roomId> <creatorName> - Create a hidden room
  exit                          - Exit admin CLI
`);
          break;

        case 'stats':
          try {
            const roomCount = await Room.countDocuments();
            const messageCount = await Message.countDocuments();
            const blockedCount = await BlockedUser.countDocuments();
            const activeRoomCount = activeRooms.size;

            // Calculate total users
            const rooms = await Room.find({});
            let totalUsers = 0;
            rooms.forEach(room => {
              totalUsers += room.users.length;
            });

            console.log(`
Server Statistics:
  Total Rooms: ${roomCount}
  Active Rooms: ${activeRoomCount}
  Total Users: ${totalUsers}
  Total Messages: ${messageCount}
  Blocked Users: ${blockedCount}
            `);
          } catch (error) {
            console.error('Error fetching stats:', error.message);
          }
          break;

        case 'list-rooms':
          try {
            const rooms = await Room.find({});
            console.log('\nAll Rooms:');
            if (rooms.length === 0) {
              console.log('  No rooms found.');
            } else {
              rooms.forEach(room => {
                const isActive = activeRooms.has(room.roomId);
                console.log(`  ${room.roomId} - ${room.name} (${room.users.length} users) ${isActive ? '[ACTIVE]' : '[INACTIVE]'} ${room.isGlobal ? '[GLOBAL]' : ''} ${room.isPrivate ? '[PRIVATE]' : ''} ${room.isHidden ? '[HIDDEN]' : ''}`);
              });
            }
          } catch (error) {
            console.error('Error listing rooms:', error.message);
          }
          break;

        case 'create-hidden-room':
          if (args.length < 2) {
            console.log('Usage: create-hidden-room <roomId> <creatorName>');
            break;
          }
          
          try {
            const [roomId, creatorName] = args;
            
            const hiddenRoom = new Room({
              roomId: roomId,
              name: `Hidden Room ${roomId}`,
              createdBy: creatorName,
              isGlobal: false,
              isPrivate: true,
              isHidden: true,
              users: [],
              pendingJoins: []
            });
            
            await hiddenRoom.save();
            console.log(`Hidden room ${roomId} created by ${creatorName}`);
            
          } catch (error) {
            console.error('Error creating hidden room:', error.message);
          }
          break;

        case 'list-blocked':
          try {
            const query = args[0] ? { roomId: args[0] } : {};
            const blockedUsers = await BlockedUser.find(query);
            console.log('\nBlocked Users:');
            if (blockedUsers.length === 0) {
              console.log('  No users are blocked.');
            } else {
              blockedUsers.forEach(user => {
                console.log(`  ${user.username} - Room: ${user.roomId} - Reason: ${user.reason} - Blocked at: ${user.blockedAt.toLocaleString()}`);
              });
            }
          } catch (error) {
            console.error('Error listing blocked users:', error.message);
          }
          break;

        case 'block':
          if (args.length < 2) {
            console.log('Usage: block <username> <roomId> [reason]');
            break;
          }

          try {
            const [username, roomId, ...reasonParts] = args;
            const reason = reasonParts.join(' ') || 'Violation of chat rules';

            // Check if user is already blocked
            const existingBlock = await BlockedUser.findOne({ username, roomId });
            if (existingBlock) {
              console.log(`User ${username} is already blocked from room ${roomId}`);
              break;
            }

            // Create block record
            const blockedUser = new BlockedUser({
              username,
              roomId,
              blockedBy: "Admin",
              reason
            });

            await blockedUser.save();

            // Find and disconnect the user if they're currently in the room
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

            console.log(`User ${username} blocked from room ${roomId}`);
          } catch (error) {
            console.error('Error blocking user:', error.message);
          }
          break;

        case 'unblock':
          if (args.length < 2) {
            console.log('Usage: unblock <username> <roomId>');
            break;
          }

          try {
            const [username, roomId] = args;

            const result = await BlockedUser.deleteOne({ username, roomId });

            if (result.deletedCount === 0) {
              console.log(`User ${username} not found in block list for room ${roomId}`);
            } else {
              console.log(`User ${username} unblocked from room ${roomId}`);
            }
          } catch (error) {
            console.error('Error unblocking user:', error.message);
          }
          break;

        case 'delete-room':
          if (args.length < 1) {
            console.log('Usage: delete-room <roomId>');
            break;
          }

          try {
            const roomId = args[0];

            if (roomId === GLOBAL_ROOM_ID) {
              console.log('Cannot delete the global room.');
              break;
            }

            // Check if room exists
            const room = await Room.findOne({ roomId });
            if (!room) {
              console.log(`Room ${roomId} does not exist.`);
              break;
            }

            // Check if room has users
            if (room.users.length > 0) {
              console.log(`Cannot delete room ${roomId} - it still has ${room.users.length} users.`);
              break;
            }

            // Delete room and its messages
            await Room.deleteOne({ roomId });
            await Message.deleteMany({ roomId });

            // Remove from active rooms
            activeRooms.delete(roomId);

            // Notify all clients about room deletion
            io.emit("room-deleted", { roomId });

            console.log(`Room ${roomId} deleted successfully`);
          } catch (error) {
            console.error('Error deleting room:', error.message);
          }
          break;

        case 'user-activity':
          try {
            const [username, roomId, limit] = args;
            let query = {};
            if (username && username !== 'null') query.username = username;
            if (roomId && roomId !== 'null') query.roomId = roomId;

            const activityLimit = parseInt(limit) || 50;
            const userActivity = await UserActivity.find(query)
              .sort({ timestamp: -1 })
              .limit(activityLimit);

            console.log('\nUser Activity:');
            if (userActivity.length === 0) {
              console.log('  No activity found.');
            } else {
              userActivity.forEach(activity => {
                console.log(`  ${activity.username} ${activity.action} ${activity.roomId} at ${activity.timestamp.toLocaleString()}`);
              });
            }
          } catch (error) {
            console.error('Error fetching user activity:', error.message);
          }
          break;

        case 'room-users':
          if (args.length < 1) {
            console.log('Usage: room-users <roomId>');
            break;
          }

          try {
            const roomId = args[0];
            const room = await Room.findOne({ roomId });

            if (!room) {
              console.log(`Room ${roomId} not found.`);
              break;
            }

            console.log(`\nUsers in room ${roomId} (${room.name}):`);
            if (room.users.length === 0) {
              console.log('  No users in this room.');
            } else {
              room.users.forEach(user => {
                const joinedTime = user.joinedAt ? user.joinedAt.toLocaleString() : 'Unknown';
                console.log(`  ${user.name} - Joined: ${joinedTime}`);
              });
            }
          } catch (error) {
            console.error('Error fetching room users:', error.message);
          }
          break;

        case 'active-users':
          try {
            console.log('\nCurrently Active Users:');
            let totalActiveUsers = 0;

            for (const [roomId, room] of activeRooms.entries()) {
              if (room.users.size > 0) {
                console.log(`\nRoom: ${roomId} (${room.name}) - ${room.users.size} users:`);
                for (const [socketId, username] of room.users.entries()) {
                  console.log(`  ${username}`);
                }
                totalActiveUsers += room.users.size;
              }
            }

            console.log(`\nTotal active users: ${totalActiveUsers}`);
          } catch (error) {
            console.error('Error fetching active users:', error.message);
          }
          break;

        case 'remove-user':
          if (args.length < 2) {
            console.log('Usage: remove-user <username> <roomId>');
            break;
          }

          try {
            const [username, roomId] = args;

            // Find the room
            const room = await Room.findOne({ roomId });
            if (!room) {
              console.log(`Room ${roomId} not found.`);
              break;
            }

            // Find the user in the room
            const userIndex = room.users.findIndex(user => user.name === username);
            if (userIndex === -1) {
              console.log(`User ${username} not found in room ${roomId}.`);
              break;
            }

            // Get socket ID before removing
            const socketId = room.users[userIndex].socketId;

            // Remove user from database
            room.users.splice(userIndex, 1);
            await room.save();

            // Remove from active rooms
            if (activeRooms.has(roomId)) {
              const activeRoom = activeRooms.get(roomId);
              activeRoom.users.delete(socketId);
            }

            // Disconnect user if they're still connected
            if (socketId) {
              io.to(socketId).emit("force-disconnect", {
                message: "You have been removed from the room by admin"
              });
              io.to(socketId).disconnectSockets(true);
            }

            // Notify room
            io.to(roomId).emit("message", {
              name: "System",
              message: `${username} was removed from the room by admin`,
              timestamp: new Date().toLocaleTimeString()
            });

            console.log(`User ${username} removed from room ${roomId}`);

            // Update room list
            updateRoomList();

          } catch (error) {
            console.error('Error removing user:', error.message);
          }
          break;

        case 'kick-user':
          if (args.length < 2) {
            console.log('Usage: kick-user <username> <roomId>');
            break;
          }

          try {
            const [username, roomId] = args;

            // Find user in active rooms
            let socketIdToKick = null;
            if (activeRooms.has(roomId)) {
              const activeRoom = activeRooms.get(roomId);
              for (const [socketId, userName] of activeRoom.users.entries()) {
                if (userName === username) {
                  socketIdToKick = socketId;
                  break;
                }
              }
            }

            if (!socketIdToKick) {
              console.log(`User ${username} not found in active room ${roomId}`);
              break;
            }

            // Force disconnect
            io.to(socketIdToKick).emit("force-disconnect", {
              message: "You have been kicked from the room by admin"
            });
            io.to(socketIdToKick).disconnectSockets(true);

            console.log(`User ${username} kicked from room ${roomId}`);

          } catch (error) {
            console.error('Error kicking user:', error.message);
          }
          break;

        case 'cleanup-users':
          try {
            let removedCount = 0;

            // Find all rooms
            const rooms = await Room.find({});

            for (const room of rooms) {
              const originalCount = room.users.length;

              // Remove users who are not in active room
              room.users = room.users.filter(user => {
                if (activeRooms.has(room.roomId)) {
                  const activeRoom = activeRooms.get(room.roomId);
                  return activeRoom.users.has(user.socketId);
                }
                return false;
              });

              if (room.users.length !== originalCount) {
                await room.save();
                removedCount += (originalCount - room.users.length);
                console.log(`Cleaned ${originalCount - room.users.length} users from room ${room.roomId}`);
              }
            }

            console.log(`Total users removed: ${removedCount}`);

          } catch (error) {
            console.error('Error cleaning up users:', error.message);
          }
          break;

        case 'pending-requests':
          if (args.length < 1) {
            console.log('Usage: pending-requests <roomId>');
            break;
          }

          try {
            const roomId = args[0];
            const room = await Room.findOne({ roomId });

            if (!room) {
              console.log(`Room ${roomId} not found.`);
              break;
            }

            console.log(`\nPending join requests for room ${roomId}:`);
            if (room.pendingJoins.length === 0) {
              console.log('  No pending requests.');
            } else {
              room.pendingJoins.forEach((request, index) => {
                console.log(`  ${index + 1}. ${request.name} (Socket: ${request.socketId}) - Requested: ${request.requestedAt.toLocaleString()}`);
              });
            }
          } catch (error) {
            console.error('Error fetching pending requests:', error.message);
          }
          break;

        case 'exit':
          console.log('Exiting admin CLI.');
          rl.close();
          break;

        default:
          console.log(`Unknown command: ${command}. Type "help" for available commands.`);
      }
    } catch (error) {
      console.error('Error executing command:', error.message);
    }

    rl.prompt();
  }).on('close', () => {
    console.log('Admin CLI closed.');
    process.exit(0);
  });
}

// Route for root path
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Stats endpoint
app.get('/stats', async (req, res) => {
  try {
    const roomCount = await Room.countDocuments();
    const userCount = await Room.aggregate([
      { $project: { userCount: { $size: "$users" } } },
      { $group: { _id: null, total: { $sum: "$userCount" } } }
    ]);
    const messageCount = await Message.countDocuments();
    
    res.json({ 
      roomCount, 
      userCount: userCount[0]?.total || 0, 
      messageCount, 
      activeConnections: io.engine.clientsCount 
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

// API to get room list
app.get("/rooms", async (req, res) => {
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
      console.log(`✅ Creator authenticated: ${username} at ${new Date().toISOString()}`);
      res.json({ success: true, message: "Creator verified" });
    } else {
      console.log(`🚨 Failed creator attempt: ${username} with token: ${creatorToken}`);
      res.json({ success: false, message: "Invalid creator token" });
    }
  } catch (error) {
    console.error("Error in creator verification:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ADMIN API ENDPOINTS (Protected with secret key)
app.delete("/admin/rooms/:roomId", async (req, res) => {
  try {
    const { roomId } = req.params;
    const { secret } = req.query;

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

    res.json({ success: true, message: `Room ${roomId} deleted successfully` });
  } catch (error) {
    console.error("Error deleting room:", error);
    res.status(500).json({ error: "Failed to delete room" });
  }
});

app.post("/admin/block-user", async (req, res) => {
  try {
    const { username, roomId, reason, secret } = req.body;

    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const existingBlock = await BlockedUser.findOne({ username, roomId });
    if (existingBlock) {
      return res.status(400).json({ error: "User is already blocked" });
    }

    const blockedUser = new BlockedUser({
      username,
      roomId,
      blockedBy: "Admin",
      reason: reason || "Violation of chat rules"
    });

    await blockedUser.save();

    const room = activeRooms.get(roomId);
    if (room) {
      for (const [socketId, userName] of room.users.entries()) {
        if (userName === username) {
          io.to(socketId).emit("blocked", { reason: `Ghost ${username}, you have been blocked: ${reason}` });
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

app.get("/admin/blocked-users", async (req, res) => {
  try {
    const { secret } = req.query;

    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { roomId } = req.query;
    const query = roomId ? { roomId } : {};
    const blockedUsers = await BlockedUser.find(query);
    res.json(blockedUsers);
  } catch (error) {
    console.error("Error fetching blocked users:", error);
    res.status(500).json({ error: "Failed to fetch blocked users" });
  }
});

app.post("/admin/unblock-user", async (req, res) => {
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

app.get("/admin/stats", async (req, res) => {
  try {
    const { secret } = req.query;

    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const roomCount = await Room.countDocuments();
    const userCount = await Room.aggregate([
      { $project: { userCount: { $size: "$users" } } },
      { $group: { _id: null, total: { $sum: "$userCount" } } }
    ]);

    const messageCount = await Message.countDocuments();
    const blockedUserCount = await BlockedUser.countDocuments();

    res.json({
      roomCount,
      userCount: userCount[0]?.total || 0,
      messageCount,
      blockedUserCount,
      activeRooms: Array.from(activeRooms.entries()).map(([id, room]) => ({
        id,
        name: room.name,
        userCount: room.users.size,
        isGlobal: room.isGlobal,
        isPrivate: room.isPrivate,
        isHidden: room.isHidden
      }))
    });
  } catch (error) {
    console.error("Error fetching stats:", error);
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

// Get user activity
app.get("/admin/user-activity", async (req, res) => {
  try {
    const { secret, username, roomId, limit } = req.query;

    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    let query = {};
    if (username) query.username = username;
    if (roomId) query.roomId = roomId;

    const activityLimit = parseInt(limit) || 100;
    const userActivity = await UserActivity.find(query)
      .sort({ timestamp: -1 })
      .limit(activityLimit);

    res.json(userActivity);
  } catch (error) {
    console.error("Error fetching user activity:", error);
    res.status(500).json({ error: "Failed to fetch user activity" });
  }
});

// Get current room users
app.get("/admin/room-users/:roomId", async (req, res) => {
  try {
    const { roomId } = req.params;
    const { secret } = req.query;

    if (secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const room = await Room.findOne({ roomId });
    if (!room) {
      return res.status(404).json({ error: "Room not found" });
    }

    res.json({
      roomId: room.roomId,
      roomName: room.name,
      users: room.users.map(user => ({
        username: user.name,
        joinedAt: user.joinedAt ? user.joinedAt.toISOString() : null
      }))
    });
  } catch (error) {
    console.error("Error fetching room users:", error);
    res.status(500).json({ error: "Failed to fetch room users" });
  }
});

app.post("/leave-room", (req, res) => {
  res.json({ success: true });
});

// Schedule cleanup job to run every hour
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

// Socket.io connection handling
io.on("connection", (socket) => {
  console.log(`User connected: ${socket.id}`);

  // Store creator tokens for this socket session
  const creatorTokens = {};

  // Rate limiting
  const messageTimestamps = [];

  socket.on("send-message", async (data) => {
    const now = Date.now();
    messageTimestamps.push(now);
    
    // Remove timestamps older than 1 second
    while (messageTimestamps.length > 0 && now - messageTimestamps[0] > 1000) {
      messageTimestamps.shift();
    }
    
    // Check if rate limit exceeded
    if (messageTimestamps.length > ADMIN_CONTROLS.MESSAGE_RATE_LIMIT) {
      socket.emit("message-error", { error: "Message rate limit exceeded" });
      return;
    }
    
    try {
      const { room, name, message } = data;
      
      // Check if user is blocked from this room
      const isBlocked = await BlockedUser.findOne({ username: name, roomId: room });
      if (isBlocked) {
        socket.emit("blocked", { reason: isBlocked.reason });
        return;
      }
      
      // Save message to database with appropriate expiration
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
      
      // Send to OTHER users in the room (not the sender)
      socket.to(room).emit("message", { 
        name: name,
        message: message,
        timestamp: new Date().toLocaleTimeString(),
        isSelf: false
      });
      
      // Send to SENDER only with different label
      socket.emit("message", {
        name: "You",
        message: message,
        timestamp: new Date().toLocaleTimeString(),
        isSelf: true
      });
      
    } catch (error) {
      console.error("Error saving message:", error);
    }
  });

  // Handle join request approvals
  socket.on("approve-join-request", async (data) => {
    try {
      const { requestSocketId, roomId } = data;
      
      // Find the room
      const roomData = await Room.findOne({ roomId: roomId });
      if (!roomData) {
        socket.emit("request-error", { error: "Room not found" });
        return;
      }

      // Check if user has permission to approve (room admin or creator)
      const isAdmin = roomData.users.some(user => 
        user.socketId === socket.id && 
        (user.name === roomData.createdBy || user.name.toLowerCase() === "pain")
      );

      if (!isAdmin) {
        socket.emit("request-error", { error: "Only room admins can approve join requests" });
        return;
      }

      // Find the pending request
      const requestIndex = roomData.pendingJoins.findIndex(req => req.socketId === requestSocketId);
      if (requestIndex === -1) {
        socket.emit("request-error", { error: "Join request not found" });
        return;
      }

      const request = roomData.pendingJoins[requestIndex];
      
      // Add user to room
      roomData.users.push({
        socketId: request.socketId,
        name: request.name,
        joinedAt: new Date()
      });
      
      // Remove from pending joins
      roomData.pendingJoins.splice(requestIndex, 1);
      await roomData.save();

      // Remove from memory
      pendingJoinRequests.delete(requestSocketId);

      // Notify the user they've been approved
      io.to(requestSocketId).emit("join-approved", { 
        room: roomId, 
        name: request.name 
      });

      // Notify room members
      io.to(roomId).emit("message", {
        name: "System",
        message: `Ghost ${request.name} joined the room`,
        timestamp: new Date().toLocaleTimeString()
      });

      // Update room list
      updateRoomList();

      console.log(`Join request approved for ${request.name} in room ${roomId}`);
    } catch (error) {
      console.error("Error approving join request:", error);
      socket.emit("request-error", { error: "Failed to approve join request" });
    }
  });

  // Handle join request rejections
  socket.on("reject-join-request", async (data) => {
    try {
      const { requestSocketId, roomId } = data;
      
      // Find the room
      const roomData = await Room.findOne({ roomId: roomId });
      if (!roomData) {
        socket.emit("request-error", { error: "Room not found" });
        return;
      }

      // Check if user has permission to reject (room admin or creator)
      const isAdmin = roomData.users.some(user => 
        user.socketId === socket.id && 
        (user.name === roomData.createdBy || user.name.toLowerCase() === "pain")
      );

      if (!isAdmin) {
        socket.emit("request-error", { error: "Only room admins can reject join requests" });
        return;
      }

      // Find the pending request
      const requestIndex = roomData.pendingJoins.findIndex(req => req.socketId === requestSocketId);
      if (requestIndex === -1) {
        socket.emit("request-error", { error: "Join request not found" });
        return;
      }

      const request = roomData.pendingJoins[requestIndex];
      
      // Remove from pending joins
      roomData.pendingJoins.splice(requestIndex, 1);
      await roomData.save();

      // Remove from memory
      pendingJoinRequests.delete(requestSocketId);

      // Notify the user they've been rejected
      io.to(requestSocketId).emit("join-rejected", { 
        room: roomId, 
        reason: "Your join request was rejected by the room admin" 
      });

      console.log(`Join request rejected for ${request.name} in room ${roomId}`);
    } catch (error) {
      console.error("Error rejecting join request:", error);
      socket.emit("request-error", { error: "Failed to reject join request" });
    }
  });

  // Create hidden room
  socket.on("create-hidden-room", async (data) => {
    try {
      const { room, name, creatorToken } = data;
      
      // Verify creator/admin permissions
      const usernameValidation = await isUsernameAvailable(name, creatorToken, socket.id);
      if (!usernameValidation.available || !usernameValidation.isCreator) {
        socket.emit("room-creation-error", { error: "Only creator/admin can create hidden rooms" });
        return;
      }

      // Check if room already exists
      const existingRoom = await Room.findOne({ roomId: room });
      if (existingRoom) {
        socket.emit("room-creation-error", { error: "Room already exists" });
        return;
      }

      // Create hidden room
      const hiddenRoom = new Room({
        roomId: room,
        name: `Hidden Room ${room}`,
        createdBy: name,
        isGlobal: false,
        isPrivate: true,
        isHidden: true,
        users: [],
        pendingJoins: []
      });

      await hiddenRoom.save();

      // Join the creator to the room immediately
      await joinRoom(socket, {
        room: room,
        name: name,
        isCreator: true,
        creatorToken: creatorToken,
        isHidden: true
      });

      socket.emit("hidden-room-created", { 
        room: room,
        message: "Hidden room created successfully. Only you can see this room."
      });

      console.log(`Hidden room ${room} created by ${name}`);
      
    } catch (error) {
      console.error("Error creating hidden room:", error);
      socket.emit("room-creation-error", { error: "Failed to create hidden room" });
    }
  });

  // Modified join-room to accept creator token
  socket.on("join-room", async (data) => {
    // Store creator token for this socket if provided
    if (data.creatorToken) {
      creatorTokens[socket.id] = data.creatorToken;
    }
    await joinRoom(socket, {
      ...data,
      creatorToken: creatorTokens[socket.id]
    });
  });

  socket.on("leave-room", async (data) => await leaveRoom(socket, data));
  socket.on("verify-admin", (data, callback) => verifyAdmin(data, callback));
  socket.on("disconnect", async (reason) => {
    // Clean up creator token
    delete creatorTokens[socket.id];
    await handleDisconnect(socket, reason);
  });
});

// Function to remove all messages by a specific user from a room
async function removeUserMessages(roomId, username) {
  try {
    console.log(`Attempting to remove messages by ${username} from ${roomId}`);
    
    const result = await Message.deleteMany({ 
      roomId: roomId, 
      name: username 
    });
    
    console.log(`Database: Removed ${result.deletedCount} messages by ${username} from room ${roomId}`);
    
    return result.deletedCount;
  } catch (error) {
    console.error("Error removing user messages:", error);
    return 0;
  }
}

// Function to notify clients to remove user messages from their view
function notifyMessageRemoval(roomId, username) {
  console.log(`Notifying room ${roomId} to remove messages by ${username}`);
  
  io.to(roomId).emit("remove-user-messages", { 
    username: username 
  });
  
  io.to(roomId).emit("message", {
    name: "System",
    message: `All messages by Ghost ${username} have been removed from the database`,
    timestamp: new Date().toLocaleTimeString()
  });
}

// Error handling
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await mongoose.connection.close();
  console.log('MongoDB connection closed through app termination');
  process.exit(0);
});

// Initialize server
const PORT = process.env.PORT || 3001;

async function startServer() {
  try {
    await initializeGlobalRoom();

    http.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🌐 Health check: http://localhost:${PORT}/health`);

      if (process.env.NODE_ENV !== 'production' || process.env.ENABLE_ADMIN_CLI === 'true') {
        setupAdminCLI();
      }
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();