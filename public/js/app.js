const API_URL = "/api/auth";

function showMessage(type, text) {
    const msgBox = document.getElementById("message");
    if (msgBox) {
        msgBox.className = `message ${type}`;
        msgBox.textContent = text;
        msgBox.style.display = "block";
    }
}

function hideMessage() {
    const msgBox = document.getElementById("message");
    if (msgBox) {
        msgBox.style.display = "none";
    }
}

function setLoading(loading) {
    const card = document.querySelector(".card");
    if (card) {
        if (loading) card.classList.add("loading");
        else card.classList.remove("loading");
    }
    const buttons = document.querySelectorAll(".btn");
    buttons.forEach(btn => {
        btn.disabled = loading;
    });
}

function clearTokens() {
    localStorage.removeItem("pendingUserId");
}

function goTo(page) {
    window.location.href = page;
}
async function apiRequest(endpoint, method = "GET", body = null) {
    const options = {
        method,
        headers: {
            "Content-Type": "application/json"
        },
        credentials: "include"
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_URL}${endpoint}`, options);
    const data = await response.json();

    if (!response.ok) {
        if (response.status === 401 && endpoint !== "/login" && endpoint !== "/status" && endpoint !== "/refresh") {
            try {
                await refreshToken();
                return await apiRequest(endpoint, method, body);
            } catch (e) {
                clearTokens();
                goTo("/");
            }
        }
        throw new Error(data.message || "Something went wrong");
    }

    return data;
}

async function register(username, password) {
    return await apiRequest("/register", "POST", { username, password });
}

async function login(username, password) {
    return await apiRequest("/login", "POST", { username, password });
}

async function logout() {
    try {
        await apiRequest("/logout", "POST");
    } catch (error) {
        console.log("Logout error:", error);
    }
    clearTokens();
    goTo("/");
}

async function getStatus() {
    return await apiRequest("/status", "GET");
}

async function setup2FA() {
    return await apiRequest("/2fa/setup", "POST");
}


async function verify2FA(token, userId = null) {
    const body = { token };
    if (userId) {
        body.userId = userId;
    }
    return await apiRequest("/2fa/verify", "POST", body);
}

async function reset2FA(currentCode) {
    return await apiRequest("/2fa/reset", "POST", { token: currentCode }); // Verify then Reset! ✅
}

async function refreshToken() {
    return await apiRequest("/refresh", "POST");
}

async function protectPage() {
    try {
        const data = await getStatus();
        if (!data.authenticated) {
            goTo("/");
            return null;
        }
        return data;
    } catch (error) {
        goTo("/");
        return null;
    }
}

async function redirectIfLoggedIn() {
    try {
        const data = await getStatus();
        if (data.authenticated) goTo("/dashboard.html");
    } catch (error) {
        // Error or Not logged in, stay on page
    }
}
