// Password protection (hashed for basic obfuscation)
const PASSWORD_HASH = '13cf3392f3445e8eff1c14396a916903'; // MD5 hash of 'claudecode'
const AUTH_COOKIE = 'course_auth_token';
const VIDEO_PASSWORD = 'claudecode';
const VIDEO_SALT = 'course_video_salt_2024';
const ENCRYPT_MARKER = 'ENCRYPTED_V1';

// Video decryption cache
const decryptedVideoCache = new Map();

// Derive encryption key using PBKDF2 (matching Node.js)
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: encoder.encode(salt),
            iterations: 100000,
            hash: 'SHA-256'
        },
        passwordKey,
        { name: 'AES-CBC', length: 256 },
        false,
        ['decrypt']
    );
}

// Decrypt video file
async function decryptVideo(arrayBuffer) {
    const data = new Uint8Array(arrayBuffer);

    // Check for encryption marker
    const marker = new TextDecoder().decode(data.slice(0, 12));
    if (marker !== ENCRYPT_MARKER) {
        // Not encrypted, return as-is
        return arrayBuffer;
    }

    // Parse encrypted file structure:
    // MARKER (12 bytes) + IV (16 bytes) + encrypted length (4 bytes) + encrypted data + remaining
    const iv = data.slice(12, 28);
    const encryptedLength = new DataView(data.buffer, 28, 4).getUint32(0);
    const encryptedData = data.slice(32, 32 + encryptedLength);
    const remainingData = data.slice(32 + encryptedLength);

    // Derive key and decrypt
    const key = await deriveKey(VIDEO_PASSWORD, VIDEO_SALT);

    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: iv },
        key,
        encryptedData
    );

    const decryptedBytes = new Uint8Array(decryptedBuffer);

    // Reconstruct original file: decrypted first 1KB + remaining data
    const result = new Uint8Array(decryptedBytes.length + remainingData.length);
    result.set(decryptedBytes, 0);
    result.set(remainingData, decryptedBytes.length);

    return result.buffer;
}

// Fetch and decrypt video, return blob URL
async function getDecryptedVideoUrl(videoPath) {
    // Check cache first
    if (decryptedVideoCache.has(videoPath)) {
        return decryptedVideoCache.get(videoPath);
    }

    const response = await fetch(videoPath);
    const encryptedBuffer = await response.arrayBuffer();
    const decryptedBuffer = await decryptVideo(encryptedBuffer);

    const blob = new Blob([decryptedBuffer], { type: 'video/mp4' });
    const blobUrl = URL.createObjectURL(blob);

    // Cache the blob URL
    decryptedVideoCache.set(videoPath, blobUrl);

    return blobUrl;
}

// Simple MD5 hash function
function md5(string) {
    function rotateLeft(value, shift) {
        return (value << shift) | (value >>> (32 - shift));
    }
    function addUnsigned(x, y) {
        const x8 = x & 0x80000000;
        const y8 = y & 0x80000000;
        const x4 = x & 0x40000000;
        const y4 = y & 0x40000000;
        const result = (x & 0x3FFFFFFF) + (y & 0x3FFFFFFF);
        if (x4 & y4) return result ^ 0x80000000 ^ x8 ^ y8;
        if (x4 | y4) {
            if (result & 0x40000000) return result ^ 0xC0000000 ^ x8 ^ y8;
            return result ^ 0x40000000 ^ x8 ^ y8;
        }
        return result ^ x8 ^ y8;
    }
    function f(x, y, z) { return (x & y) | (~x & z); }
    function g(x, y, z) { return (x & z) | (y & ~z); }
    function h(x, y, z) { return x ^ y ^ z; }
    function i(x, y, z) { return y ^ (x | ~z); }
    function ff(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(f(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function gg(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(g(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function hh(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(h(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function ii(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(i(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function convertToWordArray(string) {
        const lWordCount = (((string.length + 8) - ((string.length + 8) % 64)) / 64 + 1) * 16;
        const lWordArray = Array(lWordCount - 1).fill(0);
        let lByteCount = 0;
        let lBytePosition = 0;
        while (lByteCount < string.length) {
            lBytePosition = (lByteCount - (lByteCount % 4)) / 4;
            lWordArray[lBytePosition] |= string.charCodeAt(lByteCount) << ((lByteCount % 4) * 8);
            lByteCount++;
        }
        lBytePosition = (lByteCount - (lByteCount % 4)) / 4;
        lWordArray[lBytePosition] |= 0x80 << ((lByteCount % 4) * 8);
        lWordArray[lWordCount - 2] = string.length * 8;
        return lWordArray;
    }
    function wordToHex(value) {
        let hex = '', temp;
        for (let i = 0; i <= 3; i++) {
            temp = (value >>> (i * 8)) & 255;
            hex += ('0' + temp.toString(16)).slice(-2);
        }
        return hex;
    }
    const x = convertToWordArray(string);
    let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
    const S = [[7, 12, 17, 22], [5, 9, 14, 20], [4, 11, 16, 23], [6, 10, 15, 21]];
    const T = [
        0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
        0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
        0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
        0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
        0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
        0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
        0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
        0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
    ];
    for (let k = 0; k < x.length; k += 16) {
        const AA = a, BB = b, CC = c, DD = d;
        a = ff(a, b, c, d, x[k], S[0][0], T[0]); d = ff(d, a, b, c, x[k+1], S[0][1], T[1]);
        c = ff(c, d, a, b, x[k+2], S[0][2], T[2]); b = ff(b, c, d, a, x[k+3], S[0][3], T[3]);
        a = ff(a, b, c, d, x[k+4], S[0][0], T[4]); d = ff(d, a, b, c, x[k+5], S[0][1], T[5]);
        c = ff(c, d, a, b, x[k+6], S[0][2], T[6]); b = ff(b, c, d, a, x[k+7], S[0][3], T[7]);
        a = ff(a, b, c, d, x[k+8], S[0][0], T[8]); d = ff(d, a, b, c, x[k+9], S[0][1], T[9]);
        c = ff(c, d, a, b, x[k+10], S[0][2], T[10]); b = ff(b, c, d, a, x[k+11], S[0][3], T[11]);
        a = ff(a, b, c, d, x[k+12], S[0][0], T[12]); d = ff(d, a, b, c, x[k+13], S[0][1], T[13]);
        c = ff(c, d, a, b, x[k+14], S[0][2], T[14]); b = ff(b, c, d, a, x[k+15], S[0][3], T[15]);
        a = gg(a, b, c, d, x[k+1], S[1][0], T[16]); d = gg(d, a, b, c, x[k+6], S[1][1], T[17]);
        c = gg(c, d, a, b, x[k+11], S[1][2], T[18]); b = gg(b, c, d, a, x[k], S[1][3], T[19]);
        a = gg(a, b, c, d, x[k+5], S[1][0], T[20]); d = gg(d, a, b, c, x[k+10], S[1][1], T[21]);
        c = gg(c, d, a, b, x[k+15], S[1][2], T[22]); b = gg(b, c, d, a, x[k+4], S[1][3], T[23]);
        a = gg(a, b, c, d, x[k+9], S[1][0], T[24]); d = gg(d, a, b, c, x[k+14], S[1][1], T[25]);
        c = gg(c, d, a, b, x[k+3], S[1][2], T[26]); b = gg(b, c, d, a, x[k+8], S[1][3], T[27]);
        a = gg(a, b, c, d, x[k+13], S[1][0], T[28]); d = gg(d, a, b, c, x[k+2], S[1][1], T[29]);
        c = gg(c, d, a, b, x[k+7], S[1][2], T[30]); b = gg(b, c, d, a, x[k+12], S[1][3], T[31]);
        a = hh(a, b, c, d, x[k+5], S[2][0], T[32]); d = hh(d, a, b, c, x[k+8], S[2][1], T[33]);
        c = hh(c, d, a, b, x[k+11], S[2][2], T[34]); b = hh(b, c, d, a, x[k+14], S[2][3], T[35]);
        a = hh(a, b, c, d, x[k+1], S[2][0], T[36]); d = hh(d, a, b, c, x[k+4], S[2][1], T[37]);
        c = hh(c, d, a, b, x[k+7], S[2][2], T[38]); b = hh(b, c, d, a, x[k+10], S[2][3], T[39]);
        a = hh(a, b, c, d, x[k+13], S[2][0], T[40]); d = hh(d, a, b, c, x[k], S[2][1], T[41]);
        c = hh(c, d, a, b, x[k+3], S[2][2], T[42]); b = hh(b, c, d, a, x[k+6], S[2][3], T[43]);
        a = hh(a, b, c, d, x[k+9], S[2][0], T[44]); d = hh(d, a, b, c, x[k+12], S[2][1], T[45]);
        c = hh(c, d, a, b, x[k+15], S[2][2], T[46]); b = hh(b, c, d, a, x[k+2], S[2][3], T[47]);
        a = ii(a, b, c, d, x[k], S[3][0], T[48]); d = ii(d, a, b, c, x[k+7], S[3][1], T[49]);
        c = ii(c, d, a, b, x[k+14], S[3][2], T[50]); b = ii(b, c, d, a, x[k+5], S[3][3], T[51]);
        a = ii(a, b, c, d, x[k+12], S[3][0], T[52]); d = ii(d, a, b, c, x[k+3], S[3][1], T[53]);
        c = ii(c, d, a, b, x[k+10], S[3][2], T[54]); b = ii(b, c, d, a, x[k+1], S[3][3], T[55]);
        a = ii(a, b, c, d, x[k+8], S[3][0], T[56]); d = ii(d, a, b, c, x[k+15], S[3][1], T[57]);
        c = ii(c, d, a, b, x[k+6], S[3][2], T[58]); b = ii(b, c, d, a, x[k+13], S[3][3], T[59]);
        a = ii(a, b, c, d, x[k+4], S[3][0], T[60]); d = ii(d, a, b, c, x[k+11], S[3][1], T[61]);
        c = ii(c, d, a, b, x[k+2], S[3][2], T[62]); b = ii(b, c, d, a, x[k+9], S[3][3], T[63]);
        a = addUnsigned(a, AA); b = addUnsigned(b, BB); c = addUnsigned(c, CC); d = addUnsigned(d, DD);
    }
    return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

// Check if user is authenticated
function isAuthenticated() {
    const authToken = getCookie(AUTH_COOKIE);
    return authToken === PASSWORD_HASH;
}

// Set authentication
function setAuthenticated() {
    setCookie(AUTH_COOKIE, PASSWORD_HASH, COOKIE_DAYS);
}

// Logout
function logout() {
    deleteCookie(AUTH_COOKIE);
    decryptedVideoCache.clear();
    document.getElementById('mainContent').style.display = 'none';
    document.getElementById('loginOverlay').classList.remove('hidden');
    document.getElementById('passwordInput').value = '';
    document.getElementById('loginError').textContent = '';
    document.getElementById('passwordInput').focus();
}

// Handle login
function handleLogin(e) {
    e.preventDefault();
    const password = document.getElementById('passwordInput').value;
    const hashedPassword = md5(password);

    if (hashedPassword === PASSWORD_HASH) {
        setAuthenticated();
        document.getElementById('loginOverlay').classList.add('hidden');
        document.getElementById('mainContent').style.display = 'block';
        init();
    } else {
        const modal = document.querySelector('.login-modal');
        const error = document.getElementById('loginError');
        error.textContent = 'Incorrect password. Please try again.';
        modal.classList.add('shake');
        setTimeout(() => modal.classList.remove('shake'), 300);
        document.getElementById('passwordInput').value = '';
        document.getElementById('passwordInput').focus();
    }
}

// Check authentication on page load
document.addEventListener('DOMContentLoaded', function() {
    if (isAuthenticated()) {
        document.getElementById('loginOverlay').classList.add('hidden');
        document.getElementById('mainContent').style.display = 'block';
        init();
    } else {
        document.getElementById('loginForm').addEventListener('submit', handleLogin);
        document.getElementById('passwordInput').focus();
    }
});

// Video data with file names
const videos = [
    { id: 1, title: "Introduction to Claude Code & Software Engineering with AI Agents", file: "v01_361d72da4192.mp4", module: 1, duration: "7 min" },
    { id: 2, title: "1000X Improvement in Software Engineering Productivity with Big Prompts", file: "v02_2f674b608bc1.mp4", module: 1, duration: "12 min" },
    { id: 3, title: "One Software Engineer to Another: Let's Talk About the Fear", file: "v03_e2e94150fc86.mp4", module: 2, duration: "3 min" },
    { id: 4, title: "AI Labor: Claude Code is an AI Development Team", file: "v04_82983970188d.mp4", module: 2, duration: "5 min" },
    { id: 5, title: "The Best of N Pattern: Leverage AI Labor Cost Advantages", file: "v05_e5e74deadc84.mp4", module: 2, duration: "8 min" },
    { id: 6, title: "Can AI Judge Code Quality?", file: "v06_7ac67dc87e38.mp4", module: 3, duration: "8 min" },
    { id: 7, title: "Does AI Labor Understand Design Principles?", file: "v07_1f55be156933.mp4", module: 3, duration: "4 min" },
    { id: 8, title: "Chat, Craft, Scale: Spend More Time Designing & Innovating", file: "v08_cc3e90bf52d1.mp4", module: 3, duration: "2 min" },
    { id: 9, title: "Chat: Craft and Explore Requirements & Options", file: "v09_1fba9dd906de.mp4", module: 3, duration: "4 min" },
    { id: 10, title: "Chat: Rapid Prototyping & Personas", file: "v10_77e075e3e398.mp4", module: 3, duration: "7 min" },
    { id: 11, title: "Craft: Constraints & Prompts for Claude Code", file: "v11_c33402f966d8.mp4", module: 3, duration: "9 min" },
    { id: 12, title: "Global Persistent Context: CLAUDE.md", file: "v12_626149693ac0.mp4", module: 4, duration: "10 min" },
    { id: 13, title: "Reusable Targeted Context & Process: Claude Code Commands", file: "v13_7b4eabc11a08.mp4", module: 4, duration: "8 min" },
    { id: 14, title: "In-Context Learning: Teaching with Examples", file: "v14_b28f770c9f6d.mp4", module: 4, duration: "7 min" },
    { id: 15, title: "Claude Code, Version Control, & Git Branches", file: "v15_9e62fd8aa381.mp4", module: 5, duration: "5 min" },
    { id: 16, title: "Being Claude Code's Hands, Eyes, and Ears", file: "v16_d2e5c7fdb491.mp4", module: 6, duration: "7 min" },
    { id: 17, title: "Ensuring Claude Code Checks Its Own Work", file: "v17_d01a1c46e247.mp4", module: 6, duration: "4 min" },
    { id: 18, title: "Software Design, Token Limits, and Maintainability", file: "v18_8f8a76e451ea.mp4", module: 6, duration: "7 min" },
    { id: 19, title: "Project Structure and File Naming is Critical Context for Claude Code Scalability", file: "v19_7eea6245896d.mp4", module: 6, duration: "8 min" },
    { id: 20, title: "Start By Fixing the Process & Context, Not the Code", file: "v20_8d6c3c77d1ed.mp4", module: 7, duration: "4 min" }
];

const moduleNames = {
    1: "Module 1: Scaling Up Software Engineering",
    2: "Module 2: Leveraging the Advantages of Claude Code",
    3: "Module 3: Generative AI, Claude Code, & Code Quality",
    4: "Module 4: Building Process & Context",
    5: "Module 5: Version Control & Parallel Development",
    6: "Module 6: Improving Scalability & Reasoning",
    7: "Module 7: Multimodal Prompting & Process"
};

const COOKIE_NAME = 'claude_code_course_progress';
const COOKIE_DAYS = 365;

// State
let currentVideoId = null;
let completedVideos = new Set();

// Cookie functions
function setCookie(name, value, days) {
    const expires = new Date();
    expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
    document.cookie = `${name}=${encodeURIComponent(JSON.stringify(value))};expires=${expires.toUTCString()};path=/;SameSite=Lax`;
}

function getCookie(name) {
    const nameEQ = name + "=";
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        cookie = cookie.trim();
        if (cookie.indexOf(nameEQ) === 0) {
            try {
                return JSON.parse(decodeURIComponent(cookie.substring(nameEQ.length)));
            } catch (e) {
                return null;
            }
        }
    }
    return null;
}

function deleteCookie(name) {
    document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`;
}

// Load progress from cookies
function loadProgress() {
    const saved = getCookie(COOKIE_NAME);
    if (saved && saved.completed) {
        completedVideos = new Set(saved.completed);
        currentVideoId = saved.currentVideo || 1;
    } else {
        completedVideos = new Set();
        currentVideoId = 1;
    }
}

// Save progress to cookies
function saveProgress() {
    const data = {
        completed: Array.from(completedVideos),
        currentVideo: currentVideoId
    };
    setCookie(COOKIE_NAME, data, COOKIE_DAYS);
}

// Update UI
function updateUI() {
    // Update video items
    document.querySelectorAll('.video-item').forEach(item => {
        const videoId = parseInt(item.dataset.video);
        item.classList.toggle('completed', completedVideos.has(videoId));
        item.classList.toggle('active', videoId === currentVideoId);
    });

    // Update module progress
    document.querySelectorAll('.module').forEach(module => {
        const moduleId = parseInt(module.dataset.module);
        const moduleVideos = videos.filter(v => v.module === moduleId);
        const completedInModule = moduleVideos.filter(v => completedVideos.has(v.id)).length;
        module.querySelector('.module-progress').textContent = `${completedInModule}/${moduleVideos.length}`;
    });

    // Update overall progress
    const totalCompleted = completedVideos.size;
    const percent = Math.round((totalCompleted / videos.length) * 100);
    document.getElementById('completedCount').textContent = totalCompleted;
    document.getElementById('progressPercent').textContent = percent;
    document.getElementById('overallProgress').style.width = `${percent}%`;

    // Update navigation buttons
    document.getElementById('prevBtn').disabled = currentVideoId === 1;
    document.getElementById('nextBtn').disabled = currentVideoId === videos.length;

    // Update mark complete button
    const completeBtn = document.getElementById('markCompleteBtn');
    if (completedVideos.has(currentVideoId)) {
        completeBtn.textContent = 'Completed';
        completeBtn.classList.add('completed');
    } else {
        completeBtn.textContent = 'Mark as Complete';
        completeBtn.classList.remove('completed');
    }
}

// Load and play video
async function loadVideo(videoId) {
    const video = videos.find(v => v.id === videoId);
    if (!video) return;

    currentVideoId = videoId;

    const videoPlayer = document.getElementById('videoPlayer');
    const videoPath = 'Course_Videos/' + encodeURIComponent(video.file);

    document.getElementById('currentVideoTitle').textContent = video.title;
    document.getElementById('currentVideoModule').textContent = moduleNames[video.module];

    // Show loading state
    videoPlayer.poster = '';
    document.getElementById('currentVideoTitle').textContent = video.title + ' (Loading...)';

    try {
        // Fetch, decrypt, and create blob URL
        const blobUrl = await getDecryptedVideoUrl(videoPath);
        videoPlayer.src = blobUrl;
        document.getElementById('currentVideoTitle').textContent = video.title;
        // Auto-play video
        videoPlayer.play().catch(e => console.log('Autoplay prevented:', e));
    } catch (error) {
        console.error('Error loading video:', error);
        document.getElementById('currentVideoTitle').textContent = video.title + ' (Error loading)';
    }

    updateUI();
    saveProgress();

    // Scroll the active video into view in the sidebar
    const activeItem = document.querySelector(`.video-item[data-video="${videoId}"]`);
    if (activeItem) {
        activeItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
}

// Toggle video completion
function toggleComplete() {
    if (completedVideos.has(currentVideoId)) {
        completedVideos.delete(currentVideoId);
    } else {
        completedVideos.add(currentVideoId);
        // Add animation class
        const item = document.querySelector(`.video-item[data-video="${currentVideoId}"]`);
        if (item) {
            item.classList.add('just-completed');
            setTimeout(() => item.classList.remove('just-completed'), 500);
        }
    }
    updateUI();
    saveProgress();
}

// Navigate to previous/next video
function navigatePrev() {
    if (currentVideoId > 1) {
        loadVideo(currentVideoId - 1);
    }
}

function navigateNext() {
    if (currentVideoId < videos.length) {
        loadVideo(currentVideoId + 1);
    }
}

// Reset all progress
function resetProgress() {
    if (confirm('Are you sure you want to reset all progress? This cannot be undone.')) {
        completedVideos.clear();
        currentVideoId = 1;
        deleteCookie(COOKIE_NAME);
        loadVideo(1);
        updateUI();
    }
}

// Initialize
function init() {
    loadProgress();

    // Set up video item click handlers
    document.querySelectorAll('.video-item').forEach(item => {
        item.addEventListener('click', () => {
            loadVideo(parseInt(item.dataset.video));
        });
    });

    // Set up button handlers
    document.getElementById('prevBtn').addEventListener('click', navigatePrev);
    document.getElementById('nextBtn').addEventListener('click', navigateNext);
    document.getElementById('markCompleteBtn').addEventListener('click', toggleComplete);
    document.getElementById('resetProgress').addEventListener('click', resetProgress);
    document.getElementById('logoutBtn').addEventListener('click', logout);

    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

        switch(e.key) {
            case 'ArrowLeft':
                navigatePrev();
                break;
            case 'ArrowRight':
                navigateNext();
                break;
            case ' ':
                if (e.target.tagName !== 'VIDEO') {
                    e.preventDefault();
                    toggleComplete();
                }
                break;
        }
    });

    // Auto-mark complete when video ends
    document.getElementById('videoPlayer').addEventListener('ended', () => {
        if (!completedVideos.has(currentVideoId)) {
            completedVideos.add(currentVideoId);
            updateUI();
            saveProgress();
        }
    });

    // Load the first or last watched video
    loadVideo(currentVideoId);
    updateUI();
}

