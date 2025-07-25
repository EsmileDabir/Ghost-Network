const express = require("express");
const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http, { cors: { origin: "*" } });
const path = require("path");

// Serve static files from "public"
app.use(express.static("public"));

// Route for root path
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

io.on("connection", (socket) => {
    socket.on("join-room", ({ room, name }) => {
        socket.join(room);
        socket.to(room).emit("message", { name: "System", message: `${name} joined the room` });
    });

    socket.on("send-message", ({ room, name, message }) => {
        io.to(room).emit("message", { name, message });
    });
});

http.listen(3001, () => console.log("Server running on port 3001"));
