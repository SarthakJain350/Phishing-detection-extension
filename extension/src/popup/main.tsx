import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Popup } from "./Popup";
import "./styles.css";

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Root element not found — check popup.html");
}

createRoot(rootElement).render(
  <StrictMode>
    <Popup />
  </StrictMode>
);
