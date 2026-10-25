// Confirm dialogs and p12 password generation (no inline JS, so CSP stays strict).
document.addEventListener("submit", (e) => {
  const msg = e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});
document.addEventListener("click", (e) => {
  const id = e.target.dataset && e.target.dataset.generate;
  if (!id) return;
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  const input = document.getElementById(id);
  input.value = Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
  input.select();
});
