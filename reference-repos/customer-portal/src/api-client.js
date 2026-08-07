import axios from "axios";
import lodash from "lodash";

const { merge } = lodash;

export async function getCustomerProfile(customerId, defaults) {
  const response = await axios.get(`/api/customers/${customerId}`);
  return merge({}, defaults, response.data);
}
