const input = document.getElementById("api_url");
const saveBtn = document.getElementById("save");
const status = document.getElementById("status");

// load saved value
chrome.storage.sync.get(["api_url"], (res) => {
  if (res && res.api_url) input.value = res.api_url;
});

saveBtn.addEventListener("click", () => {
  const url = input.value.trim();
  if (!url) {
    status.innerText = "Please enter an API URL";
    return;
  }
  chrome.storage.sync.set({ api_url: url }, () => {
    status.innerText = "Saved!";
    setTimeout(() => (status.innerText = ""), 1800);
  });
});
