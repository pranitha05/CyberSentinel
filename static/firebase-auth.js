// Firebase V9+ modular SDK
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js";
import {
  getAuth,
  onAuthStateChanged,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signInWithPopup,
  GoogleAuthProvider,
  signOut
} from "https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js";
import os;

let auth, provider;
async function sendIdTokenToBackend(user) {
  try {
    const idToken = await user.getIdToken();
    const res = await fetch("https://cybersentinel-g24u.onrender.com/session-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken })
    });

    const data = await res.json();
    if (data.status === "success") {
      window.location.reload();  
    } else {
      document.getElementById("auth-error").innerText = "Session login failed.";
    }
  } catch (e) {
    document.getElementById("auth-error").innerText = "Something went wrong.";
    console.error(e);
  }
}


function setupAuthHandlers() {
  // ✏️ Register new user
  window.registerUser = async function () {
    const email = document.getElementById("login-email").value.trim();
    const password = document.getElementById("login-password").value;
    try {
      const userCred = await createUserWithEmailAndPassword(auth, email, password);
      return await sendIdTokenToBackend(userCred.user); // ✅ Return for modal
    } catch (error) {
      document.getElementById("auth-error").innerText = error.message;
    }
  };

  // 🔐 Login
  window.loginUser = async function () {
    const email = document.getElementById("login-email").value.trim();
    const password = document.getElementById("login-password").value;
    try {
      const userCred = await signInWithEmailAndPassword(auth, email, password);
      return await sendIdTokenToBackend(userCred.user); // ✅ Return for modal
    } catch (error) {
      document.getElementById("auth-error").innerText = error.message;
    }
  };

  // 🟢 Google Login
  window.googleLogin = async function () {
    try {
      const result = await signInWithPopup(auth, provider);
      return await sendIdTokenToBackend(result.user); // ✅ Return for modal
    } catch (error) {
      document.getElementById("auth-error").innerText = error.message;
    }
  };

  // 🚪 Logout
  window.logoutUser = async function () {
    try {
      await signOut(auth);
      await fetch("https://cybersentinel-g24u.onrender.com/logout", { method: "POST" });
      window.location.href = "/";
    } catch (error) {
      console.error("Logout failed:", error);
    }
  };

  // 🧠 Auth state listener
  onAuthStateChanged(auth, (user) => {
    if (user) {
      document.querySelectorAll(".requires-auth").forEach((el) => {
        el.classList.remove("disabled");
        el.onclick = () => {
          window.location.href = el.getAttribute("data-link");
        };
      });
      const logoutBtn = document.getElementById("logout-btn");
      if (logoutBtn) logoutBtn.style.display = "inline-block";
    } else {
      const protectedRoutes = ["/scanner", "/encryption", "/privacy"];
      if (protectedRoutes.includes(window.location.pathname)) {
        window.location.href = "/";
      }

      document.querySelectorAll(".requires-auth").forEach((el) => {
        el.classList.add("disabled");
        el.onclick = () => {
          document.getElementById("auth-modal").style.display = "block";
        };
      });
      const logoutBtn = document.getElementById("logout-btn");
      if (logoutBtn) logoutBtn.style.display = "none";
    }
  });
}

async function loadFirebaseConfigAndInit() {
  const firebaseConfig = {
    "apiKey": os.getenv("FIREBASE_API_KEY"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.getenv("FIREBASE_MSG_SENDER_ID"),
    "appId": os.getenv("FIREBASE_APP_ID"),
    "measurementId": os.getenv("FIREBASE_MEASUREMENT_ID")
  };

  const app = initializeApp(firebaseConfig);
  auth = getAuth(app);
  provider = new GoogleAuthProvider();

  setupAuthHandlers();
}

// 🚀 Load on page start
loadFirebaseConfigAndInit();
