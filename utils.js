// get-kibl-hex.js
import { Address } from 'libnexa-ts';

const GROUP_ADDR = 'nexa:tpjkhlhuazsgskkt5hyqn3d0e7l6vfvfg97cf42pprntks4x7vqqqcavzypmt'; // your KIBL group address
const hex = Address.fromString(GROUP_ADDR).data.toString('hex');
console.log(hex);
