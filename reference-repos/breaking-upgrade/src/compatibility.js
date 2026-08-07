import axios from "axios";

export function supportedAxiosMajorVersion() {
  // Axios 0.x does not expose VERSION consistently; Axios 1.x does.
  return (axios.VERSION ?? "0.0.0").split(".")[0];
}
