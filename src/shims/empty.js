// Browser stub for Node-only modules (tls/net). If executed, throw loudly.
export default {};
export const connect = () => { throw new Error('Node-only module used in browser'); };
