import axios from "axios";

export const clientAvailable = () => typeof axios.get === "function";
