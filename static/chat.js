const chat = document.getElementById("chat");
const form = document.getElementById("composer");
const input = document.getElementById("message");
const sendBtn = document.getElementById("send");
const suggestions = document.getElementById("suggestions");

function addMessage(text, cls) {
  const el = document.createElement("div");
  el.className = `msg ${cls}`;
  el.textContent = text;
  chat.appendChild(el);
  chat.scrollTop = chat.scrollHeight;
  return el;
}

async function sendMessage(text) {
  if (!text) return;
  addMessage(text, "user");
  input.value = "";
  sendBtn.disabled = true;

  const pending = addMessage("L'assistant consulte Wazuh…", "bot pending");

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text }),
    });
    const data = await res.json();
    pending.remove();

    if (!res.ok) {
      addMessage(data.error || "Une erreur est survenue.", "error");
    } else {
      addMessage(data.response, "bot");
    }
  } catch (err) {
    pending.remove();
    addMessage("Impossible de contacter le serveur du chatbot.", "error");
  } finally {
    sendBtn.disabled = false;
    input.focus();
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  sendMessage(input.value.trim());
});

suggestions.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-q]");
  if (btn) sendMessage(btn.dataset.q);
});

addMessage(
  "Bonjour, je suis l'assistant SOC connecté à Wazuh. Pose-moi une question sur le manager, les agents, MITRE ATT&CK, la conformité SCA, l'hygiène IT ou les événements récents.",
  "bot"
);
