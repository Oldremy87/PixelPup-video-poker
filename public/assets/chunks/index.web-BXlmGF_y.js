import { g as getDefaultExportFromCjs, r as requireBn, a as requireElliptic, b as Buffer$1, $ as $hgUW1$crypto, c as getAugmentedNamespace, p as process$1, d as requireEvents } from "./index-B2SI0-L8.js";
var freeGlobal = typeof globalThis == "object" && globalThis && globalThis.Object === Object && globalThis;
var freeSelf = typeof self == "object" && self && self.Object === Object && self;
var root = freeGlobal || freeSelf || Function("return this")();
var Symbol$1 = root.Symbol;
var objectProto$6 = Object.prototype;
var hasOwnProperty$4 = objectProto$6.hasOwnProperty;
var nativeObjectToString$1 = objectProto$6.toString;
var symToStringTag$1 = Symbol$1 ? Symbol$1.toStringTag : void 0;
function getRawTag(value) {
  var isOwn = hasOwnProperty$4.call(value, symToStringTag$1), tag = value[symToStringTag$1];
  try {
    value[symToStringTag$1] = void 0;
    var unmasked = true;
  } catch (e) {
  }
  var result = nativeObjectToString$1.call(value);
  if (unmasked) {
    if (isOwn) {
      value[symToStringTag$1] = tag;
    } else {
      delete value[symToStringTag$1];
    }
  }
  return result;
}
var objectProto$5 = Object.prototype;
var nativeObjectToString = objectProto$5.toString;
function objectToString(value) {
  return nativeObjectToString.call(value);
}
var nullTag = "[object Null]", undefinedTag = "[object Undefined]";
var symToStringTag = Symbol$1 ? Symbol$1.toStringTag : void 0;
function baseGetTag(value) {
  if (value == null) {
    return value === void 0 ? undefinedTag : nullTag;
  }
  return symToStringTag && symToStringTag in Object(value) ? getRawTag(value) : objectToString(value);
}
function isObjectLike(value) {
  return value != null && typeof value == "object";
}
var symbolTag = "[object Symbol]";
function isSymbol(value) {
  return typeof value == "symbol" || isObjectLike(value) && baseGetTag(value) == symbolTag;
}
function arrayMap(array, iteratee) {
  var index = -1, length = array == null ? 0 : array.length, result = Array(length);
  while (++index < length) {
    result[index] = iteratee(array[index], index, array);
  }
  return result;
}
var isArray = Array.isArray;
var symbolProto = Symbol$1 ? Symbol$1.prototype : void 0, symbolToString = symbolProto ? symbolProto.toString : void 0;
function baseToString(value) {
  if (typeof value == "string") {
    return value;
  }
  if (isArray(value)) {
    return arrayMap(value, baseToString) + "";
  }
  if (isSymbol(value)) {
    return symbolToString ? symbolToString.call(value) : "";
  }
  var result = value + "";
  return result == "0" && 1 / value == -Infinity ? "-0" : result;
}
var reWhitespace = /\s/;
function trimmedEndIndex(string) {
  var index = string.length;
  while (index-- && reWhitespace.test(string.charAt(index))) {
  }
  return index;
}
var reTrimStart$1 = /^\s+/;
function baseTrim(string) {
  return string ? string.slice(0, trimmedEndIndex(string) + 1).replace(reTrimStart$1, "") : string;
}
function isObject$1(value) {
  var type = typeof value;
  return value != null && (type == "object" || type == "function");
}
var NAN = 0 / 0;
var reIsBadHex = /^[-+]0x[0-9a-f]+$/i;
var reIsBinary = /^0b[01]+$/i;
var reIsOctal = /^0o[0-7]+$/i;
var freeParseInt = parseInt;
function toNumber(value) {
  if (typeof value == "number") {
    return value;
  }
  if (isSymbol(value)) {
    return NAN;
  }
  if (isObject$1(value)) {
    var other = typeof value.valueOf == "function" ? value.valueOf() : value;
    value = isObject$1(other) ? other + "" : other;
  }
  if (typeof value != "string") {
    return value === 0 ? value : +value;
  }
  value = baseTrim(value);
  var isBinary = reIsBinary.test(value);
  return isBinary || reIsOctal.test(value) ? freeParseInt(value.slice(2), isBinary ? 2 : 8) : reIsBadHex.test(value) ? NAN : +value;
}
var INFINITY = 1 / 0, MAX_INTEGER = 17976931348623157e292;
function toFinite(value) {
  if (!value) {
    return value === 0 ? value : 0;
  }
  value = toNumber(value);
  if (value === INFINITY || value === -INFINITY) {
    var sign = value < 0 ? -1 : 1;
    return sign * MAX_INTEGER;
  }
  return value === value ? value : 0;
}
function toInteger(value) {
  var result = toFinite(value), remainder = result % 1;
  return result === result ? remainder ? result - remainder : result : 0;
}
var asyncTag = "[object AsyncFunction]", funcTag$1 = "[object Function]", genTag = "[object GeneratorFunction]", proxyTag = "[object Proxy]";
function isFunction(value) {
  if (!isObject$1(value)) {
    return false;
  }
  var tag = baseGetTag(value);
  return tag == funcTag$1 || tag == genTag || tag == asyncTag || tag == proxyTag;
}
var coreJsData = root["__core-js_shared__"];
var maskSrcKey = (function() {
  var uid = /[^.]+$/.exec(coreJsData && coreJsData.keys && coreJsData.keys.IE_PROTO || "");
  return uid ? "Symbol(src)_1." + uid : "";
})();
function isMasked(func) {
  return !!maskSrcKey && maskSrcKey in func;
}
var funcProto$1 = Function.prototype;
var funcToString$1 = funcProto$1.toString;
function toSource(func) {
  if (func != null) {
    try {
      return funcToString$1.call(func);
    } catch (e) {
    }
    try {
      return func + "";
    } catch (e) {
    }
  }
  return "";
}
var reRegExpChar = /[\\^$.*+?()[\]{}|]/g;
var reIsHostCtor = /^\[object .+?Constructor\]$/;
var funcProto = Function.prototype, objectProto$4 = Object.prototype;
var funcToString = funcProto.toString;
var hasOwnProperty$3 = objectProto$4.hasOwnProperty;
var reIsNative = RegExp(
  "^" + funcToString.call(hasOwnProperty$3).replace(reRegExpChar, "\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$"
);
function baseIsNative(value) {
  if (!isObject$1(value) || isMasked(value)) {
    return false;
  }
  var pattern = isFunction(value) ? reIsNative : reIsHostCtor;
  return pattern.test(toSource(value));
}
function getValue(object, key) {
  return object == null ? void 0 : object[key];
}
function getNative(object, key) {
  var value = getValue(object, key);
  return baseIsNative(value) ? value : void 0;
}
var WeakMap$1 = getNative(root, "WeakMap");
var MAX_SAFE_INTEGER = 9007199254740991;
function isLength(value) {
  return typeof value == "number" && value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER;
}
function isArrayLike(value) {
  return value != null && isLength(value.length) && !isFunction(value);
}
var objectProto$3 = Object.prototype;
function isPrototype(value) {
  var Ctor = value && value.constructor, proto = typeof Ctor == "function" && Ctor.prototype || objectProto$3;
  return value === proto;
}
var argsTag$1 = "[object Arguments]";
function baseIsArguments(value) {
  return isObjectLike(value) && baseGetTag(value) == argsTag$1;
}
var objectProto$2 = Object.prototype;
var hasOwnProperty$2 = objectProto$2.hasOwnProperty;
var propertyIsEnumerable = objectProto$2.propertyIsEnumerable;
var isArguments = baseIsArguments(/* @__PURE__ */ (function() {
  return arguments;
})()) ? baseIsArguments : function(value) {
  return isObjectLike(value) && hasOwnProperty$2.call(value, "callee") && !propertyIsEnumerable.call(value, "callee");
};
function stubFalse() {
  return false;
}
var freeExports$1 = typeof exports == "object" && exports && !exports.nodeType && exports;
var freeModule$1 = freeExports$1 && typeof module == "object" && module && !module.nodeType && module;
var moduleExports$1 = freeModule$1 && freeModule$1.exports === freeExports$1;
var Buffer = moduleExports$1 ? root.Buffer : void 0;
var nativeIsBuffer = Buffer ? Buffer.isBuffer : void 0;
var isBuffer = nativeIsBuffer || stubFalse;
var argsTag = "[object Arguments]", arrayTag = "[object Array]", boolTag = "[object Boolean]", dateTag$1 = "[object Date]", errorTag = "[object Error]", funcTag = "[object Function]", mapTag$2 = "[object Map]", numberTag$1 = "[object Number]", objectTag$1 = "[object Object]", regexpTag = "[object RegExp]", setTag$2 = "[object Set]", stringTag$1 = "[object String]", weakMapTag$1 = "[object WeakMap]";
var arrayBufferTag = "[object ArrayBuffer]", dataViewTag$1 = "[object DataView]", float32Tag = "[object Float32Array]", float64Tag = "[object Float64Array]", int8Tag = "[object Int8Array]", int16Tag = "[object Int16Array]", int32Tag = "[object Int32Array]", uint8Tag = "[object Uint8Array]", uint8ClampedTag = "[object Uint8ClampedArray]", uint16Tag = "[object Uint16Array]", uint32Tag = "[object Uint32Array]";
var typedArrayTags = {};
typedArrayTags[float32Tag] = typedArrayTags[float64Tag] = typedArrayTags[int8Tag] = typedArrayTags[int16Tag] = typedArrayTags[int32Tag] = typedArrayTags[uint8Tag] = typedArrayTags[uint8ClampedTag] = typedArrayTags[uint16Tag] = typedArrayTags[uint32Tag] = true;
typedArrayTags[argsTag] = typedArrayTags[arrayTag] = typedArrayTags[arrayBufferTag] = typedArrayTags[boolTag] = typedArrayTags[dataViewTag$1] = typedArrayTags[dateTag$1] = typedArrayTags[errorTag] = typedArrayTags[funcTag] = typedArrayTags[mapTag$2] = typedArrayTags[numberTag$1] = typedArrayTags[objectTag$1] = typedArrayTags[regexpTag] = typedArrayTags[setTag$2] = typedArrayTags[stringTag$1] = typedArrayTags[weakMapTag$1] = false;
function baseIsTypedArray(value) {
  return isObjectLike(value) && isLength(value.length) && !!typedArrayTags[baseGetTag(value)];
}
function baseUnary(func) {
  return function(value) {
    return func(value);
  };
}
var freeExports = typeof exports == "object" && exports && !exports.nodeType && exports;
var freeModule = freeExports && typeof module == "object" && module && !module.nodeType && module;
var moduleExports = freeModule && freeModule.exports === freeExports;
var freeProcess = moduleExports && freeGlobal.process;
var nodeUtil = (function() {
  try {
    var types = freeModule && freeModule.require && freeModule.require("util").types;
    if (types) {
      return types;
    }
    return freeProcess && freeProcess.binding && freeProcess.binding("util");
  } catch (e) {
  }
})();
var nodeIsTypedArray = nodeUtil && nodeUtil.isTypedArray;
var isTypedArray = nodeIsTypedArray ? baseUnary(nodeIsTypedArray) : baseIsTypedArray;
function overArg(func, transform) {
  return function(arg) {
    return func(transform(arg));
  };
}
var nativeKeys = overArg(Object.keys, Object);
var objectProto$1 = Object.prototype;
var hasOwnProperty$1 = objectProto$1.hasOwnProperty;
function baseKeys(object) {
  if (!isPrototype(object)) {
    return nativeKeys(object);
  }
  var result = [];
  for (var key in Object(object)) {
    if (hasOwnProperty$1.call(object, key) && key != "constructor") {
      result.push(key);
    }
  }
  return result;
}
var Map$1 = getNative(root, "Map");
function toString(value) {
  return value == null ? "" : baseToString(value);
}
var DataView$1 = getNative(root, "DataView");
var Promise$1 = getNative(root, "Promise");
var Set$1 = getNative(root, "Set");
var mapTag$1 = "[object Map]", objectTag = "[object Object]", promiseTag = "[object Promise]", setTag$1 = "[object Set]", weakMapTag = "[object WeakMap]";
var dataViewTag = "[object DataView]";
var dataViewCtorString = toSource(DataView$1), mapCtorString = toSource(Map$1), promiseCtorString = toSource(Promise$1), setCtorString = toSource(Set$1), weakMapCtorString = toSource(WeakMap$1);
var getTag = baseGetTag;
if (DataView$1 && getTag(new DataView$1(new ArrayBuffer(1))) != dataViewTag || Map$1 && getTag(new Map$1()) != mapTag$1 || Promise$1 && getTag(Promise$1.resolve()) != promiseTag || Set$1 && getTag(new Set$1()) != setTag$1 || WeakMap$1 && getTag(new WeakMap$1()) != weakMapTag) {
  getTag = function(value) {
    var result = baseGetTag(value), Ctor = result == objectTag ? value.constructor : void 0, ctorString = Ctor ? toSource(Ctor) : "";
    if (ctorString) {
      switch (ctorString) {
        case dataViewCtorString:
          return dataViewTag;
        case mapCtorString:
          return mapTag$1;
        case promiseCtorString:
          return promiseTag;
        case setCtorString:
          return setTag$1;
        case weakMapCtorString:
          return weakMapTag;
      }
    }
    return result;
  };
}
var nativeMax = Math.max, nativeMin = Math.min;
function baseInRange(number, start, end) {
  return number >= nativeMin(start, end) && number < nativeMax(start, end);
}
function inRange(number, start, end) {
  start = toFinite(start);
  if (end === void 0) {
    end = start;
    start = 0;
  } else {
    end = toFinite(end);
  }
  number = toNumber(number);
  return baseInRange(number, start, end);
}
var stringTag = "[object String]";
function isString(value) {
  return typeof value == "string" || !isArray(value) && isObjectLike(value) && baseGetTag(value) == stringTag;
}
var dateTag = "[object Date]";
function baseIsDate(value) {
  return isObjectLike(value) && baseGetTag(value) == dateTag;
}
var nodeIsDate = nodeUtil && nodeUtil.isDate;
var isDate = nodeIsDate ? baseUnary(nodeIsDate) : baseIsDate;
var mapTag = "[object Map]", setTag = "[object Set]";
var objectProto = Object.prototype;
var hasOwnProperty = objectProto.hasOwnProperty;
function isEmpty(value) {
  if (value == null) {
    return true;
  }
  if (isArrayLike(value) && (isArray(value) || typeof value == "string" || typeof value.splice == "function" || isBuffer(value) || isTypedArray(value) || isArguments(value))) {
    return !value.length;
  }
  var tag = getTag(value);
  if (tag == mapTag || tag == setTag) {
    return !value.size;
  }
  if (isPrototype(value)) {
    return !baseKeys(value).length;
  }
  for (var key in value) {
    if (hasOwnProperty.call(value, key)) {
      return false;
    }
  }
  return true;
}
function isInteger$1(value) {
  return typeof value == "number" && value == toInteger(value);
}
var numberTag = "[object Number]";
function isNumber$1(value) {
  return typeof value == "number" || isObjectLike(value) && baseGetTag(value) == numberTag;
}
function isNil(value) {
  return value == null;
}
function isNull(value) {
  return value === null;
}
function isUndefined(value) {
  return value === void 0;
}
var reTrimStart = /^\s+/;
var nativeParseInt = root.parseInt;
function parseInt$1(string, radix, guard) {
  if (guard || radix == null) {
    radix = 0;
  } else if (radix) {
    radix = +radix;
  }
  return nativeParseInt(toString(string).replace(reTrimStart, ""), radix || 0);
}
var bnExports = requireBn();
const $hgUW1$bnjs = /* @__PURE__ */ getDefaultExportFromCjs(bnExports);
function add$1(number1, number2) {
  var _a;
  if (number2 === void 0) {
    number2 = "0";
  }
  var neg = 0, ind = -1;
  if (number1[0] == "-") {
    number1 = number1.substring(1);
    if (!testZero(number1)) {
      neg++;
      ind = 1;
      number1.length;
    }
  }
  if (number2[0] == "-") {
    number2 = number2.substring(1);
    if (!testZero(number2)) {
      neg++;
      ind = 2;
      number2.length;
    }
  }
  number1 = trim(number1);
  number2 = trim(number2);
  _a = pad(trim(number1), trim(number2)), number1 = _a[0], number2 = _a[1];
  if (neg == 1) {
    if (ind === 1)
      number1 = compliment(number1);
    else if (ind === 2)
      number2 = compliment(number2);
  }
  var res = addCore(number1, number2);
  if (!neg)
    return trim(res);
  else if (neg == 2)
    return "-" + trim(res);
  else {
    if (number1.length < res.length)
      return trim(res.substring(1));
    else
      return "-" + trim(compliment(res));
  }
}
function compliment(number) {
  if (testZero(number)) {
    return number;
  }
  var s = "", l = number.length, dec = number.split(".")[1], ld = dec ? dec.length : 0;
  for (var i = 0; i < l; i++) {
    if (number[i] >= "0" && number[i] <= "9")
      s += 9 - parseInt(number[i]);
    else
      s += number[i];
  }
  var one = ld > 0 ? "0." + new Array(ld).join("0") + "1" : "1";
  return addCore(s, one);
}
function trim(number) {
  var parts = number.split(".");
  if (!parts[0])
    parts[0] = "0";
  while (parts[0][0] == "0" && parts[0].length > 1)
    parts[0] = parts[0].substring(1);
  return parts[0] + (parts[1] ? "." + parts[1] : "");
}
function pad(number1, number2) {
  var parts1 = number1.split("."), parts2 = number2.split(".");
  var length1 = parts1[0].length, length2 = parts2[0].length;
  if (length1 > length2) {
    parts2[0] = new Array(Math.abs(length1 - length2) + 1).join("0") + (parts2[0] ? parts2[0] : "");
  } else {
    parts1[0] = new Array(Math.abs(length1 - length2) + 1).join("0") + (parts1[0] ? parts1[0] : "");
  }
  length1 = parts1[1] ? parts1[1].length : 0, length2 = parts2[1] ? parts2[1].length : 0;
  if (length1 || length2) {
    if (length1 > length2) {
      parts2[1] = (parts2[1] ? parts2[1] : "") + new Array(Math.abs(length1 - length2) + 1).join("0");
    } else {
      parts1[1] = (parts1[1] ? parts1[1] : "") + new Array(Math.abs(length1 - length2) + 1).join("0");
    }
  }
  number1 = parts1[0] + (parts1[1] ? "." + parts1[1] : "");
  number2 = parts2[0] + (parts2[1] ? "." + parts2[1] : "");
  return [number1, number2];
}
function addCore(number1, number2) {
  var _a;
  _a = pad(number1, number2), number1 = _a[0], number2 = _a[1];
  var sum = "", carry = 0;
  for (var i = number1.length - 1; i >= 0; i--) {
    if (number1[i] === ".") {
      sum = "." + sum;
      continue;
    }
    var temp = parseInt(number1[i]) + parseInt(number2[i]) + carry;
    sum = temp % 10 + sum;
    carry = Math.floor(temp / 10);
  }
  return carry ? carry.toString() + sum : sum;
}
function testZero(number) {
  return /^0[0]*[.]{0,1}[0]*$/.test(number);
}
function abs(n) {
  if (typeof n == "number" || typeof n == "bigint")
    n = n.toString();
  if (n[0] == "-")
    return n.substring(1);
  return n;
}
var RoundingModes;
(function(RoundingModes2) {
  RoundingModes2[RoundingModes2["CEILING"] = 0] = "CEILING";
  RoundingModes2[RoundingModes2["DOWN"] = 1] = "DOWN";
  RoundingModes2[RoundingModes2["FLOOR"] = 2] = "FLOOR";
  RoundingModes2[RoundingModes2["HALF_DOWN"] = 3] = "HALF_DOWN";
  RoundingModes2[RoundingModes2["HALF_EVEN"] = 4] = "HALF_EVEN";
  RoundingModes2[RoundingModes2["HALF_UP"] = 5] = "HALF_UP";
  RoundingModes2[RoundingModes2["UNNECESSARY"] = 6] = "UNNECESSARY";
  RoundingModes2[RoundingModes2["UP"] = 7] = "UP";
})(RoundingModes || (RoundingModes = {}));
function roundOff(input, n, mode) {
  if (n === void 0) {
    n = 0;
  }
  if (mode === void 0) {
    mode = RoundingModes.HALF_EVEN;
  }
  if (mode === RoundingModes.UNNECESSARY) {
    throw new Error("UNNECESSARY Rounding Mode has not yet been implemented");
  }
  if (typeof input == "number" || typeof input == "bigint")
    input = input.toString();
  var neg = false;
  if (input[0] === "-") {
    neg = true;
    input = input.substring(1);
  }
  var parts = input.split("."), partInt = parts[0], partDec = parts[1];
  if (n < 0) {
    n = -n;
    if (partInt.length <= n)
      return "0";
    else {
      var prefix = partInt.substr(0, partInt.length - n);
      input = prefix + "." + partInt.substr(partInt.length - n) + partDec;
      prefix = roundOff(input, 0, mode);
      return (neg ? "-" : "") + prefix + new Array(n + 1).join("0");
    }
  }
  if (n == 0) {
    partInt.length;
    if (greaterThanFive(parts[1], partInt, neg, mode)) {
      partInt = increment(partInt);
    }
    return (neg && parseInt(partInt) ? "-" : "") + partInt;
  }
  if (!parts[1]) {
    return (neg ? "-" : "") + partInt + "." + new Array(n + 1).join("0");
  } else if (parts[1].length < n) {
    return (neg ? "-" : "") + partInt + "." + parts[1] + new Array(n - parts[1].length + 1).join("0");
  }
  partDec = parts[1].substring(0, n);
  var rem = parts[1].substring(n);
  if (rem && greaterThanFive(rem, partDec, neg, mode)) {
    partDec = increment(partDec);
    if (partDec.length > n) {
      return (neg ? "-" : "") + increment(partInt, parseInt(partDec[0])) + "." + partDec.substring(1);
    }
  }
  return (neg && (parseInt(partInt) || parseInt(partDec)) ? "-" : "") + partInt + "." + partDec;
}
function greaterThanFive(part, pre, neg, mode) {
  if (!part || part === new Array(part.length + 1).join("0"))
    return false;
  if (mode === RoundingModes.DOWN || !neg && mode === RoundingModes.FLOOR || neg && mode === RoundingModes.CEILING)
    return false;
  if (mode === RoundingModes.UP || neg && mode === RoundingModes.FLOOR || !neg && mode === RoundingModes.CEILING)
    return true;
  var five = "5" + new Array(part.length).join("0");
  if (part > five)
    return true;
  else if (part < five)
    return false;
  switch (mode) {
    case RoundingModes.HALF_DOWN:
      return false;
    case RoundingModes.HALF_UP:
      return true;
    case RoundingModes.HALF_EVEN:
    default:
      return parseInt(pre[pre.length - 1]) % 2 == 1;
  }
}
function increment(part, c) {
  if (c === void 0) {
    c = 0;
  }
  if (!c)
    c = 1;
  if (typeof part == "number")
    part.toString();
  var l = part.length - 1, s = "";
  for (var i = l; i >= 0; i--) {
    var x = parseInt(part[i]) + c;
    if (x == 10) {
      c = 1;
      x = 0;
    } else {
      c = 0;
    }
    s += x;
  }
  if (c)
    s += c;
  return s.split("").reverse().join("");
}
function stripTrailingZero(number) {
  var isNegative = number[0] === "-";
  if (isNegative) {
    number = number.substr(1);
  }
  while (number[0] == "0") {
    number = number.substr(1);
  }
  if (number.indexOf(".") != -1) {
    while (number[number.length - 1] == "0") {
      number = number.substr(0, number.length - 1);
    }
  }
  if (number == "" || number == ".") {
    number = "0";
  } else if (number[number.length - 1] == ".") {
    number = number.substr(0, number.length - 1);
  }
  if (number[0] == ".") {
    number = "0" + number;
  }
  if (isNegative && number != "0") {
    number = "-" + number;
  }
  return number;
}
function multiply(number1, number2) {
  number1 = number1.toString();
  number2 = number2.toString();
  var negative = 0;
  if (number1[0] == "-") {
    negative++;
    number1 = number1.substr(1);
  }
  if (number2[0] == "-") {
    negative++;
    number2 = number2.substr(1);
  }
  number1 = stripTrailingZero(number1);
  number2 = stripTrailingZero(number2);
  var decimalLength1 = 0;
  var decimalLength2 = 0;
  if (number1.indexOf(".") != -1) {
    decimalLength1 = number1.length - number1.indexOf(".") - 1;
  }
  if (number2.indexOf(".") != -1) {
    decimalLength2 = number2.length - number2.indexOf(".") - 1;
  }
  var decimalLength = decimalLength1 + decimalLength2;
  number1 = stripTrailingZero(number1.replace(".", ""));
  number2 = stripTrailingZero(number2.replace(".", ""));
  if (number1.length < number2.length) {
    var temp = number1;
    number1 = number2;
    number2 = temp;
  }
  if (number2 == "0") {
    return "0";
  }
  var length = number2.length;
  var carry = 0;
  var positionVector = [];
  var currentPosition = length - 1;
  var result = "";
  for (var i = 0; i < length; i++) {
    positionVector[i] = number1.length - 1;
  }
  for (var i = 0; i < 2 * number1.length; i++) {
    var sum = 0;
    for (var j = number2.length - 1; j >= currentPosition && j >= 0; j--) {
      if (positionVector[j] > -1 && positionVector[j] < number1.length) {
        sum += parseInt(number1[positionVector[j]--]) * parseInt(number2[j]);
      }
    }
    sum += carry;
    carry = Math.floor(sum / 10);
    result = sum % 10 + result;
    currentPosition--;
  }
  result = stripTrailingZero(adjustDecimal(result, decimalLength));
  if (negative == 1) {
    result = "-" + result;
  }
  return result;
}
function adjustDecimal(number, decimal) {
  if (decimal == 0)
    return number;
  else {
    number = decimal >= number.length ? new Array(decimal - number.length + 1).join("0") + number : number;
    return number.substr(0, number.length - decimal) + "." + number.substr(number.length - decimal, decimal);
  }
}
function divide(dividend, divisor, precission, mode) {
  if (precission === void 0) {
    precission = 8;
  }
  if (mode === void 0) {
    mode = RoundingModes.HALF_EVEN;
  }
  if (divisor == 0) {
    throw new Error("Cannot divide by 0");
  }
  dividend = dividend.toString();
  divisor = divisor.toString();
  dividend = dividend.replace(/(\.\d*?[1-9])0+$/g, "$1").replace(/\.0+$/, "");
  divisor = divisor.replace(/(\.\d*?[1-9])0+$/g, "$1").replace(/\.0+$/, "");
  if (dividend == 0)
    return "0";
  var neg = 0;
  if (divisor[0] == "-") {
    divisor = divisor.substring(1);
    neg++;
  }
  if (dividend[0] == "-") {
    dividend = dividend.substring(1);
    neg++;
  }
  var pt_dvsr = divisor.indexOf(".") > 0 ? divisor.length - divisor.indexOf(".") - 1 : -1;
  divisor = trim(divisor.replace(".", ""));
  if (pt_dvsr >= 0) {
    var pt_dvnd = dividend.indexOf(".") > 0 ? dividend.length - dividend.indexOf(".") - 1 : -1;
    if (pt_dvnd == -1) {
      dividend = trim(dividend + new Array(pt_dvsr + 1).join("0"));
    } else {
      if (pt_dvsr > pt_dvnd) {
        dividend = dividend.replace(".", "");
        dividend = trim(dividend + new Array(pt_dvsr - pt_dvnd + 1).join("0"));
      } else if (pt_dvsr < pt_dvnd) {
        dividend = dividend.replace(".", "");
        var loc = dividend.length - pt_dvnd + pt_dvsr;
        dividend = trim(dividend.substring(0, loc) + "." + dividend.substring(loc));
      } else if (pt_dvsr == pt_dvnd) {
        dividend = trim(dividend.replace(".", ""));
      }
    }
  }
  var prec = 0, dl = divisor.length, quotent = "";
  var dvnd = dividend.indexOf(".") > -1 && dividend.indexOf(".") < dl ? dividend.substring(0, dl + 1) : dividend.substring(0, dl);
  dividend = dividend.indexOf(".") > -1 && dividend.indexOf(".") < dl ? dividend.substring(dl + 1) : dividend.substring(dl);
  if (dvnd.indexOf(".") > -1) {
    var shift = dvnd.length - dvnd.indexOf(".") - 1;
    dvnd = dvnd.replace(".", "");
    if (dl > dvnd.length) {
      shift += dl - dvnd.length;
      dvnd = dvnd + new Array(dl - dvnd.length + 1).join("0");
    }
    prec = shift;
    quotent = "0." + new Array(shift).join("0");
  }
  precission = precission + 2;
  while (prec <= precission) {
    var qt = 0;
    while (parseInt(dvnd) >= parseInt(divisor)) {
      dvnd = add$1(dvnd, "-" + divisor);
      qt++;
    }
    quotent += qt;
    if (!dividend) {
      if (!prec)
        quotent += ".";
      prec++;
      dvnd = dvnd + "0";
    } else {
      if (dividend[0] == ".") {
        quotent += ".";
        prec++;
        dividend = dividend.substring(1);
      }
      dvnd = dvnd + dividend.substring(0, 1);
      dividend = dividend.substring(1);
    }
  }
  return (neg == 1 ? "-" : "") + trim(roundOff(quotent, precission - 2, mode));
}
function subtract(number1, number2) {
  number1 = number1.toString();
  number2 = number2.toString();
  number2 = negate(number2);
  return add$1(number1, number2);
}
function negate(number) {
  if (number[0] == "-") {
    number = number.substr(1);
  } else {
    number = "-" + number;
  }
  return number;
}
function modulus(dividend, divisor) {
  if (divisor == 0) {
    throw new Error("Cannot divide by 0");
  }
  dividend = dividend.toString();
  divisor = divisor.toString();
  validate(dividend);
  validate(divisor);
  var sign = "";
  if (dividend[0] == "-") {
    sign = "-";
    dividend = dividend.substr(1);
  }
  if (divisor[0] == "-") {
    divisor = divisor.substr(1);
  }
  var result = subtract(dividend, multiply(divisor, roundOff(divide(dividend, divisor), 0, RoundingModes.FLOOR)));
  return sign + result;
}
function validate(oparand) {
  if (oparand.indexOf(".") != -1) {
    throw new Error("Modulus of non-integers not supported");
  }
}
function compareTo(number1, number2) {
  var _a, _b;
  var negative = false;
  _a = [number1, number2].map(function(n) {
    return stripTrailingZero(n);
  }), number1 = _a[0], number2 = _a[1];
  if (number1[0] == "-" && number2[0] != "-") {
    return -1;
  } else if (number1[0] != "-" && number2[0] == "-") {
    return 1;
  } else if (number1[0] == "-" && number2[0] == "-") {
    number1 = number1.substr(1);
    number2 = number2.substr(1);
    negative = true;
  }
  _b = pad(number1, number2), number1 = _b[0], number2 = _b[1];
  if (number1.localeCompare(number2) == 0) {
    return 0;
  }
  for (var i = 0; i < number1.length; i++) {
    if (number1[i] == number2[i]) {
      continue;
    } else if (number1[i] > number2[i]) {
      if (negative) {
        return -1;
      } else {
        return 1;
      }
    } else {
      if (negative) {
        return 1;
      } else {
        return -1;
      }
    }
  }
  return 0;
}
var bigDecimal = (
  /** @class */
  (function() {
    function bigDecimal2(number) {
      if (number === void 0) {
        number = "0";
      }
      this.value = bigDecimal2.validate(number);
    }
    bigDecimal2.validate = function(number) {
      if (number) {
        number = number.toString();
        if (isNaN(number))
          throw Error("Parameter is not a number: " + number);
        if (number[0] == "+")
          number = number.substring(1);
      } else
        number = "0";
      if (number.startsWith("."))
        number = "0" + number;
      else if (number.startsWith("-."))
        number = "-0" + number.substr(1);
      if (/e/i.test(number)) {
        var _a = number.split(/[eE]/), mantisa = _a[0], exponent = _a[1];
        mantisa = trim(mantisa);
        var sign = "";
        if (mantisa[0] == "-") {
          sign = "-";
          mantisa = mantisa.substring(1);
        }
        if (mantisa.indexOf(".") >= 0) {
          exponent = parseInt(exponent) + mantisa.indexOf(".");
          mantisa = mantisa.replace(".", "");
        } else {
          exponent = parseInt(exponent) + mantisa.length;
        }
        if (mantisa.length < exponent) {
          number = sign + mantisa + new Array(exponent - mantisa.length + 1).join("0");
        } else if (mantisa.length >= exponent && exponent > 0) {
          number = sign + trim(mantisa.substring(0, exponent)) + (mantisa.length > exponent ? "." + mantisa.substring(exponent) : "");
        } else {
          number = sign + "0." + new Array(-exponent + 1).join("0") + mantisa;
        }
      }
      return number;
    };
    bigDecimal2.prototype.getValue = function() {
      return this.value;
    };
    bigDecimal2.prototype.setValue = function(num) {
      this.value = bigDecimal2.validate(num);
    };
    bigDecimal2.getPrettyValue = function(number, digits, separator) {
      if (digits === void 0) {
        digits = 3;
      }
      if (separator === void 0) {
        separator = ",";
      }
      number = bigDecimal2.validate(number);
      var neg = number.charAt(0) == "-";
      if (neg)
        number = number.substring(1);
      var len = number.indexOf(".");
      len = len > 0 ? len : number.length;
      var temp = "";
      for (var i = len; i > 0; ) {
        if (i < digits) {
          digits = i;
          i = 0;
        } else
          i -= digits;
        temp = number.substring(i, i + digits) + (i < len - digits && i >= 0 ? separator : "") + temp;
      }
      return (neg ? "-" : "") + temp + number.substring(len);
    };
    bigDecimal2.prototype.getPrettyValue = function(digits, separator) {
      if (digits === void 0) {
        digits = 3;
      }
      if (separator === void 0) {
        separator = ",";
      }
      return bigDecimal2.getPrettyValue(this.value, digits, separator);
    };
    bigDecimal2.round = function(number, precision, mode) {
      if (precision === void 0) {
        precision = 0;
      }
      if (mode === void 0) {
        mode = RoundingModes.HALF_EVEN;
      }
      number = bigDecimal2.validate(number);
      if (isNaN(precision))
        throw Error("Precision is not a number: " + precision);
      return roundOff(number, precision, mode);
    };
    bigDecimal2.prototype.round = function(precision, mode) {
      if (precision === void 0) {
        precision = 0;
      }
      if (mode === void 0) {
        mode = RoundingModes.HALF_EVEN;
      }
      if (isNaN(precision))
        throw Error("Precision is not a number: " + precision);
      return new bigDecimal2(roundOff(this.value, precision, mode));
    };
    bigDecimal2.abs = function(number) {
      number = bigDecimal2.validate(number);
      return abs(number);
    };
    bigDecimal2.prototype.abs = function() {
      return new bigDecimal2(abs(this.value));
    };
    bigDecimal2.floor = function(number) {
      number = bigDecimal2.validate(number);
      if (number.indexOf(".") === -1)
        return number;
      return bigDecimal2.round(number, 0, RoundingModes.FLOOR);
    };
    bigDecimal2.prototype.floor = function() {
      if (this.value.indexOf(".") === -1)
        return new bigDecimal2(this.value);
      return new bigDecimal2(this.value).round(0, RoundingModes.FLOOR);
    };
    bigDecimal2.ceil = function(number) {
      number = bigDecimal2.validate(number);
      if (number.indexOf(".") === -1)
        return number;
      return bigDecimal2.round(number, 0, RoundingModes.CEILING);
    };
    bigDecimal2.prototype.ceil = function() {
      if (this.value.indexOf(".") === -1)
        return new bigDecimal2(this.value);
      return new bigDecimal2(this.value).round(0, RoundingModes.CEILING);
    };
    bigDecimal2.add = function(number1, number2) {
      number1 = bigDecimal2.validate(number1);
      number2 = bigDecimal2.validate(number2);
      return add$1(number1, number2);
    };
    bigDecimal2.prototype.add = function(number) {
      return new bigDecimal2(add$1(this.value, number.getValue()));
    };
    bigDecimal2.subtract = function(number1, number2) {
      number1 = bigDecimal2.validate(number1);
      number2 = bigDecimal2.validate(number2);
      return subtract(number1, number2);
    };
    bigDecimal2.prototype.subtract = function(number) {
      return new bigDecimal2(subtract(this.value, number.getValue()));
    };
    bigDecimal2.multiply = function(number1, number2) {
      number1 = bigDecimal2.validate(number1);
      number2 = bigDecimal2.validate(number2);
      return multiply(number1, number2);
    };
    bigDecimal2.prototype.multiply = function(number) {
      return new bigDecimal2(multiply(this.value, number.getValue()));
    };
    bigDecimal2.divide = function(number1, number2, precision, mode) {
      number1 = bigDecimal2.validate(number1);
      number2 = bigDecimal2.validate(number2);
      return divide(number1, number2, precision, mode);
    };
    bigDecimal2.prototype.divide = function(number, precision, mode) {
      return new bigDecimal2(divide(this.value, number.getValue(), precision, mode));
    };
    bigDecimal2.modulus = function(number1, number2) {
      number1 = bigDecimal2.validate(number1);
      number2 = bigDecimal2.validate(number2);
      return modulus(number1, number2);
    };
    bigDecimal2.prototype.modulus = function(number) {
      return new bigDecimal2(modulus(this.value, number.getValue()));
    };
    bigDecimal2.compareTo = function(number1, number2) {
      number1 = bigDecimal2.validate(number1);
      number2 = bigDecimal2.validate(number2);
      return compareTo(number1, number2);
    };
    bigDecimal2.prototype.compareTo = function(number) {
      return compareTo(this.value, number.getValue());
    };
    bigDecimal2.negate = function(number) {
      number = bigDecimal2.validate(number);
      return negate(number);
    };
    bigDecimal2.prototype.negate = function() {
      return new bigDecimal2(negate(this.value));
    };
    bigDecimal2.stripTrailingZero = function(number) {
      number = bigDecimal2.validate(number);
      return stripTrailingZero(number);
    };
    bigDecimal2.prototype.stripTrailingZero = function() {
      return new bigDecimal2(stripTrailingZero(this.value));
    };
    bigDecimal2.RoundingModes = RoundingModes;
    return bigDecimal2;
  })()
);
var ellipticExports = requireElliptic();
const $hgUW1$elliptic = /* @__PURE__ */ getDefaultExportFromCjs(ellipticExports);
function base(ALPHABET2) {
  if (ALPHABET2.length >= 255) {
    throw new TypeError("Alphabet too long");
  }
  const BASE_MAP = new Uint8Array(256);
  for (let j = 0; j < BASE_MAP.length; j++) {
    BASE_MAP[j] = 255;
  }
  for (let i = 0; i < ALPHABET2.length; i++) {
    const x = ALPHABET2.charAt(i);
    const xc = x.charCodeAt(0);
    if (BASE_MAP[xc] !== 255) {
      throw new TypeError(x + " is ambiguous");
    }
    BASE_MAP[xc] = i;
  }
  const BASE = ALPHABET2.length;
  const LEADER = ALPHABET2.charAt(0);
  const FACTOR = Math.log(BASE) / Math.log(256);
  const iFACTOR = Math.log(256) / Math.log(BASE);
  function encode(source) {
    if (source instanceof Uint8Array) ;
    else if (ArrayBuffer.isView(source)) {
      source = new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    } else if (Array.isArray(source)) {
      source = Uint8Array.from(source);
    }
    if (!(source instanceof Uint8Array)) {
      throw new TypeError("Expected Uint8Array");
    }
    if (source.length === 0) {
      return "";
    }
    let zeroes = 0;
    let length = 0;
    let pbegin = 0;
    const pend = source.length;
    while (pbegin !== pend && source[pbegin] === 0) {
      pbegin++;
      zeroes++;
    }
    const size = (pend - pbegin) * iFACTOR + 1 >>> 0;
    const b58 = new Uint8Array(size);
    while (pbegin !== pend) {
      let carry = source[pbegin];
      let i = 0;
      for (let it1 = size - 1; (carry !== 0 || i < length) && it1 !== -1; it1--, i++) {
        carry += 256 * b58[it1] >>> 0;
        b58[it1] = carry % BASE >>> 0;
        carry = carry / BASE >>> 0;
      }
      if (carry !== 0) {
        throw new Error("Non-zero carry");
      }
      length = i;
      pbegin++;
    }
    let it2 = size - length;
    while (it2 !== size && b58[it2] === 0) {
      it2++;
    }
    let str = LEADER.repeat(zeroes);
    for (; it2 < size; ++it2) {
      str += ALPHABET2.charAt(b58[it2]);
    }
    return str;
  }
  function decodeUnsafe(source) {
    if (typeof source !== "string") {
      throw new TypeError("Expected String");
    }
    if (source.length === 0) {
      return new Uint8Array();
    }
    let psz = 0;
    let zeroes = 0;
    let length = 0;
    while (source[psz] === LEADER) {
      zeroes++;
      psz++;
    }
    const size = (source.length - psz) * FACTOR + 1 >>> 0;
    const b256 = new Uint8Array(size);
    while (psz < source.length) {
      const charCode = source.charCodeAt(psz);
      if (charCode > 255) {
        return;
      }
      let carry = BASE_MAP[charCode];
      if (carry === 255) {
        return;
      }
      let i = 0;
      for (let it3 = size - 1; (carry !== 0 || i < length) && it3 !== -1; it3--, i++) {
        carry += BASE * b256[it3] >>> 0;
        b256[it3] = carry % 256 >>> 0;
        carry = carry / 256 >>> 0;
      }
      if (carry !== 0) {
        throw new Error("Non-zero carry");
      }
      length = i;
      psz++;
    }
    let it4 = size - length;
    while (it4 !== size && b256[it4] === 0) {
      it4++;
    }
    const vch = new Uint8Array(zeroes + (size - it4));
    let j = zeroes;
    while (it4 !== size) {
      vch[j++] = b256[it4++];
    }
    return vch;
  }
  function decode(string) {
    const buffer = decodeUnsafe(string);
    if (buffer) {
      return buffer;
    }
    throw new Error("Non-base" + BASE + " character");
  }
  return {
    encode,
    decodeUnsafe,
    decode
  };
}
var ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const $hgUW1$bs58 = base(ALPHABET);
var $parcel$global$1 = globalThis;
var $df64573ef6d51081$exports$1 = {};
$df64573ef6d51081$exports$1 = JSON.parse('{"name":"libnexa-ts","version":"1.0.6","description":"A pure and powerful Nexa SDK library.","type":"module","source":"src/index.ts","types":"dist/index.d.ts","main":"dist/index.cjs","module":"dist/index.mjs","browser":"dist/index.web.mjs","exports":{"types":"./dist/index.d.ts","node":{"import":"./dist/index.mjs","require":"./dist/index.cjs"},"browser":"./dist/index.web.mjs","default":"./dist/index.mjs"},"targets":{"main":{"context":"node","outputFormat":"commonjs","distDir":"dist","isLibrary":true,"includeNodeModules":["lodash-es"]},"module":{"context":"node","outputFormat":"esmodule","distDir":"dist","isLibrary":true},"browser":{"context":"browser","outputFormat":"esmodule","distDir":"dist","isLibrary":true}},"files":["dist"],"scripts":{"check":"tsc --noEmit && npm run madge","build":"del-cli ./dist && parcel build","lint":"eslint .","madge":"madge --circular src/index.ts","test":"vitest run --dir tests","coverage":"del-cli ./coverage && npm test -- --coverage --reporter=verbose --reporter=junit","docs":"typedoc"},"keywords":["nexa","blockchain"],"repository":{"type":"git","url":"https://gitlab.com/nexa/libnexa-ts"},"author":"vgrunner","license":"MIT","dependencies":{"bn.js":"^5.2.2","bs58":"^6.0.0","elliptic":"^6.6.1","js-big-decimal":"^2.2.0","lodash-es":"^4.17.21"},"devDependencies":{"@parcel/packager-ts":"^2.15.4","@parcel/transformer-typescript-types":"^2.15.4","@types/bn.js":"^5.2.0","@types/elliptic":"^6.4.18","@types/lodash-es":"^4.17.12","@types/node":"^24.0.8","@vitest/coverage-v8":"^3.2.4","del-cli":"^6.0.0","eslint":"^9.30.0","madge":"^8.0.0","parcel":"^2.15.4","typedoc":"^0.28.7","typedoc-plugin-markdown":"^4.7.0","typedoc-plugin-rename-defaults":"^0.7.3","typescript":"^5.8.3","typescript-eslint":"^8.35.1","vitest":"^3.0.6"},"@parcel/resolver-default":{"packageExports":true},"madge":{"detectiveOptions":{"ts":{"skipTypeImports":true}}}}');
class $e44f707fde477092$export$2e2bcd8739ae039 {
  static validateState(condition, message) {
    if (!condition) throw new Error(`Invalid State: ${message}`);
  }
  static validateArgument(condition, argumentName, message = "") {
    if (!condition) throw new Error(`Invalid Argument: ${argumentName}. ${message}`);
  }
  static validateArgumentType(argument, type, argumentName) {
    argumentName = argumentName || "(unknown name)";
    if (isString(type)) {
      if (type === "Buffer") {
        if (!Buffer$1.isBuffer(argument)) throw new TypeError(`Invalid Argument for ${argumentName}, expected ${type} but got ${typeof argument}`);
      } else if (typeof argument !== type) throw new TypeError(`Invalid Argument for ${argumentName}, expected ${type} but got ${typeof argument}`);
    } else {
      if (!(argument instanceof type)) throw new TypeError(`Invalid Argument for ${argumentName}, expected ${type} but got ${typeof argument}`);
    }
  }
}
class $9f918c10ad4fef51$export$2e2bcd8739ae039 {
  /**
  * Fill a buffer with a value.
  *
  * @param buffer
  * @param value
  * @return filled buffer
  * 
  * @deprecated use `buffer.fill(value)`
  */
  static fill(buffer, value) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(buffer, "Buffer", "buffer");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(value, "number", "value");
    return buffer.fill(value);
  }
  /**
  *
  * @param original buffer
  * @return Return a copy of a buffer
  * 
  * @deprecated use `Buffer.from(original) or Buffer.copyBytesFrom(original)`
  */
  static copy(original) {
    let buffer = Buffer$1.alloc(original.length);
    original.copy(buffer);
    return buffer;
  }
  /**
  * Tests for both node's Buffer and Uint8Array
  *
  * @param arg
  * @return Returns true if the given argument is an instance of a buffer. 
  */
  static isBuffer(arg) {
    return Buffer$1.isBuffer(arg) || arg instanceof Uint8Array;
  }
  /**
  * Tests for both node's Buffer and Uint8Array
  *
  * @param arg
  * @return Returns true if the given argument is an instance of a hash160 or hash256 buffer. 
  */
  static isHashBuffer(arg) {
    return this.isBuffer(arg) && (arg.length === 20 || arg.length === 32);
  }
  /**
  * Returns a zero-filled byte array
  *
  * @param length
  * 
  * @deprecated use `Buffer.alloc(length)`
  */
  static emptyBuffer(length) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(length, "number", "length");
    return Buffer$1.alloc(length);
  }
  /**
  * Reverse a buffer
  * @param param
  * @return new reversed buffer
  */
  static reverse(param) {
    return Buffer$1.from(param).reverse();
  }
  /**
  * Transforms a buffer into a string with a number in hexa representation
  *
  * Shorthand for <tt>buffer.toString('hex')</tt>
  *
  * @param buffer
  * @return string
  */
  static bufferToHex(buffer) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(buffer, "Buffer", "buffer");
    return buffer.toString("hex");
  }
  /**
  * Transforms a number from 0 to 255 into a Buffer of size 1 with that value
  *
  * @param integer
  * @return Buffer
  */
  static integerAsSingleByteBuffer(integer) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(integer, "number", "integer");
    return Buffer$1.from([
      integer & 255
    ]);
  }
  /**
  * Transforms the first byte of an array into a number ranging from -128 to 127
  * 
  * @param buffer
  * @return number
  */
  static integerFromSingleByteBuffer(buffer) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(buffer, "Buffer", "buffer");
    return buffer[0];
  }
  /**
  * Transform a 4-byte integer into a Buffer of length 4.
  *
  * @param integer
  * @return Buffer
  */
  static integerAsBuffer(integer) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(integer, "number", "integer");
    let bytes = [];
    bytes.push(integer >> 24 & 255);
    bytes.push(integer >> 16 & 255);
    bytes.push(integer >> 8 & 255);
    bytes.push(integer & 255);
    return Buffer$1.from(bytes);
  }
  /**
  * Transform the first 4 values of a Buffer into a number, in little endian encoding
  *
  * @param buffer
  * @return integer
  */
  static integerFromBuffer(buffer) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(buffer, "Buffer", "buffer");
    return buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3];
  }
  /* secure random bytes that sometimes throws an error due to lack of entropy */
  static getRandomBuffer(size) {
    return $hgUW1$crypto.randomBytes(size);
  }
}
class $62ca61b6ba036e1b$export$2e2bcd8739ae039 {
  static sha1(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf", "Must be Buffer");
    return $hgUW1$crypto.createHash("sha1").update(buf).digest();
  }
  static sha256(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf", "Must be Buffer");
    return $hgUW1$crypto.createHash("sha256").update(buf).digest();
  }
  static sha512(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf", "Must be Buffer");
    return $hgUW1$crypto.createHash("sha512").update(buf).digest();
  }
  static ripemd160(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf", "Must be Buffer");
    return $hgUW1$crypto.createHash("ripemd160").update(buf).digest();
  }
  static sha256sha256(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf", "Must be Buffer");
    return this.sha256(this.sha256(buf));
  }
  static sha256ripemd160(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf", "Must be Buffer");
    return this.ripemd160(this.sha256(buf));
  }
  static sha256hmac(data, key) {
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.hmac($62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256, 512, data, key);
  }
  static sha512hmac(data, key) {
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.hmac($62ca61b6ba036e1b$export$2e2bcd8739ae039.sha512, 1024, data, key);
  }
  static hmac(hashf, size, data, key) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(data), "data", "Must be Buffer");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(key), "key", "Must be Buffer");
    let blocksize = size / 8;
    if (key.length > blocksize) key = hashf(key);
    else if (key.length < blocksize) {
      let fill = Buffer$1.alloc(blocksize);
      fill.fill(0);
      key.copy(fill);
      key = fill;
    }
    let o_key = Buffer$1.alloc(blocksize);
    o_key.fill(92);
    let i_key = Buffer$1.alloc(blocksize);
    i_key.fill(54);
    let o_key_pad = Buffer$1.alloc(blocksize);
    let i_key_pad = Buffer$1.alloc(blocksize);
    for (let i = 0; i < blocksize; i++) {
      o_key_pad[i] = o_key[i] ^ key[i];
      i_key_pad[i] = i_key[i] ^ key[i];
    }
    return hashf(Buffer$1.concat([
      o_key_pad,
      hashf(Buffer$1.concat([
        i_key_pad,
        data
      ]))
    ]));
  }
}
class $c337f7a9455509cf$export$2e2bcd8739ae039 {
  /**
  * Determines whether a string contains only hexadecimal values
  * 
  * @param value
  * @returns true if the string is the hexa representation of a number
  */
  static isHexa(value) {
    return isString(value) && value.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(value);
  }
  /**
  * Test if an argument is a valid JSON object. If it is, returns a truthy
  * value (the json object decoded), so no double JSON.parse call is necessary
  *
  * @param arg
  * @return false if the argument is not a JSON string.
  */
  static isValidJSON(arg) {
    if (!isString(arg)) return false;
    try {
      return JSON.parse(arg);
    } catch {
      return false;
    }
  }
  static cloneArray(array) {
    return [
      ...array
    ];
  }
  /**
  * Checks that a value is a natural number.
  *
  * @param value
  * @return true if a positive integer or zero.
  */
  static isNaturalNumber(value) {
    return typeof value === "number" && isFinite(value) && Math.floor(value) === value && value >= 0;
  }
  /**
  * Checks that a value is a natural number.
  *
  * @param value
  * @return true if a positive integer or zero.
  */
  static isNaturalBigInt(value) {
    return typeof value === "bigint" && value >= 0n;
  }
}
class $5aa97aebe18a7924$export$2e2bcd8739ae039 extends $hgUW1$bnjs {
  static {
    this.Zero = new $5aa97aebe18a7924$export$2e2bcd8739ae039(0);
  }
  static {
    this.One = new $5aa97aebe18a7924$export$2e2bcd8739ae039(1);
  }
  static {
    this.Minus1 = new $5aa97aebe18a7924$export$2e2bcd8739ae039(-1);
  }
  static fromNumber(num) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isNumber$1(num), "num");
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(num);
  }
  static fromBigInt(num) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(typeof num === "bigint", "num");
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(num.toString());
  }
  static fromString(str, base2) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(str), "str");
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(str, base2);
  }
  static fromBuffer(buf, opts) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf");
    if (opts?.endian === "little") buf = $9f918c10ad4fef51$export$2e2bcd8739ae039.reverse(buf);
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(buf.toString("hex"), 16);
  }
  /**
  * Create a BN from a "ScriptNum":
  * This is analogous to the constructor for CScriptNum in nexad. Many ops in
  * nexad's script interpreter use CScriptNum, which is not really a proper
  * bignum. Instead, an error is thrown if trying to input a number bigger than
  * 4 bytes. We copy that behavior here. A third argument, `size`, is provided to
  * extend the hard limit of 4 bytes, as some usages require more than 4 bytes.
  */
  static fromScriptNumBuffer(buf, fRequireMinimal, size) {
    let nMaxNumSize = size || 4;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(buf.length <= nMaxNumSize, "script number overflow");
    if (fRequireMinimal && buf.length > 0) {
      if ((buf[buf.length - 1] & 127) === 0) {
        if (buf.length <= 1 || (buf[buf.length - 2] & 128) === 0) throw new Error("non-minimally encoded script number");
      }
    }
    return $5aa97aebe18a7924$export$2e2bcd8739ae039.fromSM(buf, {
      endian: "little"
    });
  }
  // Override arithmetic methods to ensure they return BNExtended instances
  add(b) {
    const result = super.add(b).toString();
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(result);
  }
  sub(b) {
    const result = super.sub(b).toString();
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(result);
  }
  mul(b) {
    const result = super.mul(b).toString();
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(result);
  }
  mod(b) {
    const result = super.mod(b).toString();
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(result);
  }
  umod(b) {
    const result = super.umod(b).toString();
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(result);
  }
  toNumber() {
    return parseInt(this.toString(10), 10);
  }
  toBigInt() {
    return BigInt(this.toString(10));
  }
  toBuffer(opts, length) {
    if (isString(opts))
      return super.toBuffer(opts, length);
    let hex = this.toString(16, 2);
    let buf = Buffer$1.from(hex, "hex");
    if (opts?.size) {
      let natlen = hex.length / 2;
      if (natlen > opts.size) buf = $5aa97aebe18a7924$export$2e2bcd8739ae039.trim(buf, natlen);
      else if (natlen < opts.size) buf = $5aa97aebe18a7924$export$2e2bcd8739ae039.pad(buf, natlen, opts.size);
    }
    if (opts?.endian === "little") buf = $9f918c10ad4fef51$export$2e2bcd8739ae039.reverse(buf);
    return buf;
  }
  /**
  * The corollary to the above, with the notable exception that we do not throw
  * an error if the output is larger than four bytes. (Which can happen if
  * performing a numerical operation that results in an overflow to more than 4
  * bytes).
  */
  toScriptNumBuffer() {
    return this.toSM({
      endian: "little"
    });
  }
  toScriptBigNumBuffer() {
    return this.toSM({
      endian: "little",
      bignum: true
    });
  }
  getSize() {
    const bin = this.toString(2).replace("-", "");
    const numBits = bin.length + 1;
    return numBits / 8;
  }
  safeAdd(bigNumToAdd, maxSize) {
    const sum = this.add(bigNumToAdd);
    this.checkOperationForOverflow(bigNumToAdd, sum, maxSize);
    return sum;
  }
  safeSub(bigNumToSubtract, maxSize) {
    const difference = this.sub(bigNumToSubtract);
    this.checkOperationForOverflow(bigNumToSubtract, difference, maxSize);
    return difference;
  }
  safeMul(bigNumToMultiply, maxSize) {
    const product = this.mul(bigNumToMultiply);
    this.checkOperationForOverflow(bigNumToMultiply, product, maxSize);
    return product;
  }
  checkOperationForOverflow(operand, result, maxSize) {
    if (this.getSize() > maxSize || operand.getSize() > maxSize || result.getSize() > 8) throw new Error("overflow");
  }
  toSMBigEndian() {
    let buf;
    if (this.cmp($5aa97aebe18a7924$export$2e2bcd8739ae039.Zero) === -1) {
      buf = this.neg().toBuffer();
      if (buf[0] & 128) buf = Buffer$1.concat([
        Buffer$1.from([
          128
        ]),
        buf
      ]);
      else buf[0] = buf[0] | 128;
    } else {
      buf = this.toBuffer();
      if (buf[0] & 128) buf = Buffer$1.concat([
        Buffer$1.from([
          0
        ]),
        buf
      ]);
    }
    if (buf.length === 1 && buf[0] === 0) buf = Buffer$1.from([]);
    return buf;
  }
  toBigNumSMBigEndian() {
    let buf;
    if (this.cmp($5aa97aebe18a7924$export$2e2bcd8739ae039.Zero) === -1) {
      buf = this.neg().toBuffer();
      buf = Buffer$1.concat([
        Buffer$1.from([
          128
        ]),
        buf
      ]);
    } else {
      buf = this.toBuffer();
      buf = Buffer$1.concat([
        Buffer$1.from([
          0
        ]),
        buf
      ]);
    }
    return buf;
  }
  toSM(opts) {
    let buf = opts?.bignum ? this.toBigNumSMBigEndian() : this.toSMBigEndian();
    if (opts?.endian === "little") buf = $9f918c10ad4fef51$export$2e2bcd8739ae039.reverse(buf);
    return buf;
  }
  /**
  * Instantiate a BigNumber from a "signed magnitude buffer"
  * (a buffer where the most significant bit represents the sign (0 = positive, -1 = negative))
  */
  static fromSM(buf, opts) {
    if (buf.length === 0) return this.fromBuffer(Buffer$1.from([
      0
    ]));
    if (opts?.endian === "little") buf = $9f918c10ad4fef51$export$2e2bcd8739ae039.reverse(buf);
    let ret;
    if (buf[0] & 128) {
      buf[0] = buf[0] & 127;
      ret = this.fromBuffer(buf);
      ret.neg().copy(ret);
    } else ret = this.fromBuffer(buf);
    return ret;
  }
  static trim(buf, natlen) {
    return buf.subarray(natlen - buf.length, natlen);
  }
  static pad(buf, natlen, size) {
    let rbuf = Buffer$1.alloc(size);
    for (let i = 0; i < buf.length; i++) rbuf[rbuf.length - 1 - i] = buf[buf.length - 1 - i];
    for (let i = 0; i < size - natlen; i++) rbuf[i] = 0;
    return rbuf;
  }
}
class $12fea2c2eb591556$export$2e2bcd8739ae039 {
  constructor(buf) {
    this.finished = this.eof;
    this.buf = Buffer$1.from([]);
    this.pos = 0;
    if (isUndefined(buf)) return;
    if (Buffer$1.isBuffer(buf)) this.set({
      buf
    });
    else if (isString(buf)) {
      let b = Buffer$1.from(buf, "hex");
      if (b.length * 2 != buf.length) throw new TypeError("Invalid hex string");
      this.set({
        buf: b
      });
    } else if (isObject$1(buf)) {
      let obj = buf;
      this.set(obj);
    } else throw new TypeError("Unrecognized argument for BufferReader");
  }
  set(obj) {
    this.buf = obj.buf || this.buf;
    this.pos = obj.pos || this.pos || 0;
    return this;
  }
  eof() {
    return this.pos >= this.buf.length;
  }
  read(len) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(len), "Must specify a length");
    let buf = this.buf.subarray(this.pos, this.pos + len);
    this.pos = this.pos + len;
    return buf;
  }
  readAll() {
    let buf = this.buf.subarray(this.pos, this.buf.length);
    this.pos = this.buf.length;
    return buf;
  }
  readUInt8() {
    let val = this.buf.readUInt8(this.pos);
    this.pos = this.pos + 1;
    return val;
  }
  readUInt16BE() {
    let val = this.buf.readUInt16BE(this.pos);
    this.pos = this.pos + 2;
    return val;
  }
  readUInt16LE() {
    let val = this.buf.readUInt16LE(this.pos);
    this.pos = this.pos + 2;
    return val;
  }
  readUInt32BE() {
    let val = this.buf.readUInt32BE(this.pos);
    this.pos = this.pos + 4;
    return val;
  }
  readUInt32LE() {
    let val = this.buf.readUInt32LE(this.pos);
    this.pos = this.pos + 4;
    return val;
  }
  readInt32LE() {
    let val = this.buf.readInt32LE(this.pos);
    this.pos = this.pos + 4;
    return val;
  }
  readUInt64BEBN() {
    let buf = this.buf.subarray(this.pos, this.pos + 8);
    let bn = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(buf);
    this.pos = this.pos + 8;
    return bn;
  }
  readUInt64LEBN() {
    let second = this.buf.readUInt32LE(this.pos);
    let first = this.buf.readUInt32LE(this.pos + 4);
    let combined = first * 4294967296 + second;
    let bn;
    if (combined <= 9007199254740991) bn = new $5aa97aebe18a7924$export$2e2bcd8739ae039(combined);
    else {
      let data = this.buf.subarray(this.pos, this.pos + 8);
      bn = new $5aa97aebe18a7924$export$2e2bcd8739ae039(data, 10, "le");
    }
    this.pos = this.pos + 8;
    return bn;
  }
  readVarintNum() {
    let first = this.readUInt8();
    switch (first) {
      case 253:
        return this.readUInt16LE();
      case 254:
        return this.readUInt32LE();
      case 255:
        let bn = this.readUInt64LEBN();
        let n = bn.toNumber();
        if (n <= Math.pow(2, 53)) return n;
        else throw new Error("number too large to retain precision - use readVarintBN");
    }
    return first;
  }
  /**
  * reads a length prepended buffer
  */
  readVarLengthBuffer() {
    let len = this.readVarintNum();
    let buf = this.read(len);
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(buf.length === len, "Invalid length while reading varlength buffer. Expected to read: " + len + " and read " + buf.length);
    return buf;
  }
  readVarintBuf() {
    let first = this.buf.readUInt8(this.pos);
    switch (first) {
      case 253:
        return this.read(3);
      case 254:
        return this.read(5);
      case 255:
        return this.read(9);
      default:
        return this.read(1);
    }
  }
  readVarintBN() {
    let first = this.readUInt8();
    switch (first) {
      case 253:
        return new $5aa97aebe18a7924$export$2e2bcd8739ae039(this.readUInt16LE());
      case 254:
        return new $5aa97aebe18a7924$export$2e2bcd8739ae039(this.readUInt32LE());
      case 255:
        return this.readUInt64LEBN();
      default:
        return new $5aa97aebe18a7924$export$2e2bcd8739ae039(first);
    }
  }
  reverse() {
    let buf = $9f918c10ad4fef51$export$2e2bcd8739ae039.reverse(this.buf);
    this.buf = buf;
    return this;
  }
  readReverse(len) {
    if (isUndefined(len)) len = this.buf.length;
    let buf = this.buf.subarray(this.pos, this.pos + len);
    this.pos = this.pos + len;
    return $9f918c10ad4fef51$export$2e2bcd8739ae039.reverse(buf);
  }
  readCoreVarintNum() {
    let n = 0;
    while (true) {
      let chData = this.readUInt8();
      n = n << 7 | chData & 127;
      if (chData & 128) n++;
      else return n;
    }
  }
}
class $35852622c8c617e8$export$2e2bcd8739ae039 {
  constructor(obj) {
    this.bufs = [];
    this.bufLen = 0;
    if (obj) this.set(obj);
  }
  set(obj) {
    this.bufs = obj.bufs || this.bufs;
    this.bufLen = this.bufs.reduce((prev, buf) => prev + buf.length, 0);
    return this;
  }
  toBuffer() {
    return this.concat();
  }
  concat() {
    return Buffer$1.concat(this.bufs, this.bufLen);
  }
  write(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf");
    this.bufs.push(buf);
    this.bufLen += buf.length;
    return this;
  }
  writeReverse(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf");
    this.bufs.push($9f918c10ad4fef51$export$2e2bcd8739ae039.reverse(buf));
    this.bufLen += buf.length;
    return this;
  }
  writeUInt8(n) {
    let buf = Buffer$1.alloc(1);
    buf.writeUInt8(n, 0);
    this.write(buf);
    return this;
  }
  writeUInt16BE(n) {
    let buf = Buffer$1.alloc(2);
    buf.writeUInt16BE(n, 0);
    this.write(buf);
    return this;
  }
  writeUInt16LE(n) {
    let buf = Buffer$1.alloc(2);
    buf.writeUInt16LE(n, 0);
    this.write(buf);
    return this;
  }
  writeUInt32BE(n) {
    let buf = Buffer$1.alloc(4);
    buf.writeUInt32BE(n, 0);
    this.write(buf);
    return this;
  }
  writeInt32LE(n) {
    let buf = Buffer$1.alloc(4);
    buf.writeInt32LE(n, 0);
    this.write(buf);
    return this;
  }
  writeUInt32LE(n) {
    let buf = Buffer$1.alloc(4);
    buf.writeUInt32LE(n, 0);
    this.write(buf);
    return this;
  }
  writeUInt64BEBN(bn) {
    let buf = bn.toBuffer({
      size: 8
    });
    this.write(buf);
    return this;
  }
  writeUInt64LEBN(bn) {
    let buf = bn.toBuffer({
      size: 8
    });
    this.writeReverse(buf);
    return this;
  }
  writeVarintNum(n) {
    let buf = $35852622c8c617e8$export$2e2bcd8739ae039.varintBufNum(n);
    this.write(buf);
    return this;
  }
  writeVarintBN(bn) {
    let buf = $35852622c8c617e8$export$2e2bcd8739ae039.varintBufBN(bn);
    this.write(buf);
    return this;
  }
  writeVarLengthBuf(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf");
    this.writeVarintNum(buf.length);
    this.write(buf);
    return this;
  }
  writeCoreVarintNum(n) {
    let tmp = [];
    let len = 0;
    while (true) {
      tmp.push(n & 127 | (len ? 128 : 0));
      if (n <= 127) break;
      n = (n >> 7) - 1;
      len++;
    }
    this.write(Buffer$1.from(tmp).reverse());
    return this;
  }
  static varintBufNum(n) {
    let buf = void 0;
    if (n < 253) {
      buf = Buffer$1.alloc(1);
      buf.writeUInt8(n, 0);
    } else if (n < 65536) {
      buf = Buffer$1.alloc(3);
      buf.writeUInt8(253, 0);
      buf.writeUInt16LE(n, 1);
    } else if (n < 4294967296) {
      buf = Buffer$1.alloc(5);
      buf.writeUInt8(254, 0);
      buf.writeUInt32LE(n, 1);
    } else {
      buf = Buffer$1.alloc(9);
      buf.writeUInt8(255, 0);
      buf.writeInt32LE(n & -1, 1);
      buf.writeUInt32LE(Math.floor(n / 4294967296), 5);
    }
    return buf;
  }
  static varintBufBN(bn) {
    let buf = void 0;
    let n = bn.toNumber();
    if (n < 253) {
      buf = Buffer$1.alloc(1);
      buf.writeUInt8(n, 0);
    } else if (n < 65536) {
      buf = Buffer$1.alloc(3);
      buf.writeUInt8(253, 0);
      buf.writeUInt16LE(n, 1);
    } else if (n < 4294967296) {
      buf = Buffer$1.alloc(5);
      buf.writeUInt8(254, 0);
      buf.writeUInt32LE(n, 1);
    } else {
      let bw = new $35852622c8c617e8$export$2e2bcd8739ae039();
      bw.writeUInt8(255);
      bw.writeUInt64LEBN(bn);
      buf = bw.concat();
    }
    return buf;
  }
}
class $05e660d5daa855e4$export$2e2bcd8739ae039 {
  /**
  *  Converts `value` into a decimal string, assuming `unit` decimal
  *  places. The `unit` may be the number of decimal places or the enum of
  *  a unit (e.g. ``UnitType.MEX`` for 8 decimal places).
  *
  */
  static formatUnits(value, unit) {
    let decimals = 2;
    if (!isNil(unit)) {
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isInteger$1(unit) && unit >= 0, "unit", "invalid unit");
      decimals = unit;
    }
    return bigDecimal.divide(value, Math.pow(10, decimals), decimals);
  }
  /**
  *  Converts the decimal string `value` to a BigInt, assuming
  *  `unit` decimal places. The `unit` may the number of decimal places
  *  or the name of a unit (e.g. ``UnitType.KEX`` for 5 decimal places).
  */
  static parseUnits(value, unit) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(value), "value", "must be a string");
    let decimals = 2;
    if (!isNil(unit)) {
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isInteger$1(unit) && unit >= 0, "unit", "invalid unit");
      decimals = unit;
    }
    return BigInt(bigDecimal.multiply(value, Math.pow(10, decimals)));
  }
  /**
  *  Converts `value` into a decimal string using 2 decimal places.
  */
  static formatNEXA(sats) {
    return this.formatUnits(sats, 2);
  }
  /**
  *  Converts the decimal string `NEXA` to a BigInt, using 2 decimal places.
  */
  static parseNEXA(nexa) {
    return this.parseUnits(nexa, 2);
  }
}
class $ddbf68ec49150fba$export$95be4ae94445245a {
  constructor(params) {
    this.name = params.name;
    this.alias = params.alias;
    this.prefix = params.prefix;
    this.pubkeyhash = params.pubkeyhash;
    this.privatekey = params.privatekey;
    this.scripthash = params.scripthash;
    this.xpubkey = params.xpubkey;
    this.xprivkey = params.xprivkey;
    this.networkMagic = $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(params.networkMagic);
    this.port = params.port;
    this.dnsSeeds = params.dnsSeeds;
  }
  toString() {
    return this.name;
  }
}
const $ddbf68ec49150fba$export$673894bea0cfc1c8 = new $ddbf68ec49150fba$export$95be4ae94445245a({
  name: "mainnet",
  alias: "livenet",
  prefix: "nexa",
  pubkeyhash: 25,
  privatekey: 35,
  scripthash: 68,
  xpubkey: 1114203936,
  xprivkey: 1114401651,
  networkMagic: 1915163169,
  port: 7228,
  dnsSeeds: [
    "seed.nextchain.cash",
    "seeder.nexa.org",
    "nexa-seeder.bitcoinunlimited.info"
  ]
});
const $ddbf68ec49150fba$export$2cc9cef11fee0dca = new $ddbf68ec49150fba$export$95be4ae94445245a({
  name: "testnet",
  alias: "testnet",
  prefix: "nexatest",
  pubkeyhash: 111,
  privatekey: 239,
  scripthash: 196,
  xpubkey: 70617039,
  xprivkey: 70615956,
  networkMagic: 1915163170,
  port: 7230,
  dnsSeeds: [
    "nexa-testnet-seeder.bitcoinunlimited.info",
    "testnetseeder.nexa.org"
  ]
});
class $a89918d61ea4dca0$export$2e2bcd8739ae039 {
  static {
    this._instance = new $a89918d61ea4dca0$export$2e2bcd8739ae039();
  }
  get mainnet() {
    return $ddbf68ec49150fba$export$673894bea0cfc1c8;
  }
  /** @deprecated use mainnet */
  get livenet() {
    return $ddbf68ec49150fba$export$673894bea0cfc1c8;
  }
  get testnet() {
    return $ddbf68ec49150fba$export$2cc9cef11fee0dca;
  }
  get defaultNetwork() {
    return this._defaultNetwork;
  }
  set defaultNetwork(network) {
    this._defaultNetwork = network;
  }
  /**
  * @returns the singleton instance of NetworkManager
  */
  static getInstance() {
    return this._instance;
  }
  get(arg, key) {
    if (arg instanceof $ddbf68ec49150fba$export$95be4ae94445245a) {
      if (this.networks.includes(arg)) return arg;
      if (this.networks.map((n) => n.name).includes(arg.name)) return this.networks.find((n) => n.name == arg.name);
    }
    if (key) return this.networks.find((network) => {
      if (key == "networkMagic") return $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(network[key]) == arg;
      else return network[key] == arg;
    });
    else return this.networks.find((network) => Object.keys(network).some((prop) => {
      let _prop = prop;
      if (_prop == "networkMagic") return $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(network[_prop]) == arg;
      else return network[_prop] == arg;
    }));
  }
  create(network) {
    return new $ddbf68ec49150fba$export$95be4ae94445245a(network);
  }
  add(network) {
    if (!(network instanceof $ddbf68ec49150fba$export$95be4ae94445245a)) network = new $ddbf68ec49150fba$export$95be4ae94445245a(network);
    this.networks.push(network);
  }
  remove(network) {
    if (typeof network !== "object") {
      network = this.get(network);
      if (!network) return;
    }
    for (let i = 0; i < this.networks.length; i++) if (this.networks[i] === network || JSON.stringify(this.networks[i]) == JSON.stringify(network)) this.networks.splice(i, 1);
  }
  constructor() {
    this.networks = [
      $ddbf68ec49150fba$export$673894bea0cfc1c8,
      $ddbf68ec49150fba$export$2cc9cef11fee0dca
    ];
    this._defaultNetwork = $ddbf68ec49150fba$export$673894bea0cfc1c8;
  }
}
const $a89918d61ea4dca0$export$f09b1917886389c3 = $a89918d61ea4dca0$export$2e2bcd8739ae039.getInstance();
class $369a157b63fbc3fd$export$2e2bcd8739ae039 {
  constructor(params) {
    this.r = params.r;
    this.s = params.s;
    this.i = params.i;
    this.compressed = params.compressed;
  }
  toBuffer(isSchnorr = true) {
    if (isSchnorr)
      return Buffer$1.concat([
        this.r.toBuffer({
          size: 32
        }),
        this.s.toBuffer({
          size: 32
        })
      ]);
    let rnbuf = this.r.toBuffer();
    let snbuf = this.s.toBuffer();
    let rneg = rnbuf[0] & 128 ? true : false;
    let sneg = snbuf[0] & 128 ? true : false;
    let rbuf = rneg ? Buffer$1.concat([
      Buffer$1.from([
        0
      ]),
      rnbuf
    ]) : rnbuf;
    let sbuf = sneg ? Buffer$1.concat([
      Buffer$1.from([
        0
      ]),
      snbuf
    ]) : snbuf;
    let rlength = rbuf.length;
    let slength = sbuf.length;
    let length = 2 + rlength + 2 + slength;
    let rheader = 2;
    let sheader = 2;
    let header = 48;
    let der = Buffer$1.concat([
      Buffer$1.from([
        header,
        length,
        rheader,
        rlength
      ]),
      rbuf,
      Buffer$1.from([
        sheader,
        slength
      ]),
      sbuf
    ]);
    return der;
  }
  toTxFormat(sighashBuf) {
    let sigbuf = this.toBuffer();
    if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(sighashBuf)) return Buffer$1.concat([
      sigbuf,
      sighashBuf
    ]);
    return sigbuf;
  }
  toString() {
    return this.toBuffer().toString("hex");
  }
  /**
  * Schnorr signatures are 64 bytes: r [len] 32 || s [len] 32.
  * 
  * There can be a few more bytes that is the sighashtype. It needs to be trimmed before calling this.
  */
  static fromBuffer(buf, strict) {
    if (buf.length === 64) {
      let params = this.parseSchnorrEncodedSig(buf);
      return new $369a157b63fbc3fd$export$2e2bcd8739ae039(params);
    }
    let obj = $369a157b63fbc3fd$export$2e2bcd8739ae039.parseDER(buf, strict);
    return new $369a157b63fbc3fd$export$2e2bcd8739ae039({
      r: obj.r,
      s: obj.s
    });
  }
  /**
  * The format used in a tx.
  * schnorr is 64 bytes, the rest are sighashtype bytes
  * 
  * @param buf 
  */
  static fromTxFormat(buf) {
    let sigbuf = buf.subarray(0, 64);
    return $369a157b63fbc3fd$export$2e2bcd8739ae039.fromBuffer(sigbuf);
  }
  /**
  * This assumes the str is a raw signature and does not have sighashtype.
  * Use {@link Signature.fromTxString} when decoding a tx
  * 
  * @param str the signature hex string
  * @see fromTxString
  */
  static fromString(str) {
    let buf = Buffer$1.from(str, "hex");
    return $369a157b63fbc3fd$export$2e2bcd8739ae039.fromBuffer(buf);
  }
  /**
  * This assumes the str might have sighashtype bytes and will trim it if needed.
  * Use this when decoding a tx signature string
  * 
  * @param str the tx signature hex string
  */
  static fromTxString(str, encoding = "hex") {
    return $369a157b63fbc3fd$export$2e2bcd8739ae039.fromTxFormat(Buffer$1.from(str, encoding));
  }
  static parseSchnorrEncodedSig(buf) {
    let r = buf.subarray(0, 32);
    let s = buf.subarray(32, 64);
    return {
      r: $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(r),
      s: $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(s)
    };
  }
  /**
  * For ECDSA. In order to mimic the non-strict DER encoding of OpenSSL, set strict = false.
  */
  static parseDER(buf, strict) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "DER formatted signature should be a buffer");
    if (isUndefined(strict)) strict = true;
    let header = buf[0];
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(header === 48, "Header byte should be 0x30");
    let length = buf[1];
    let buflength = buf.subarray(2).length;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!strict || length === buflength, "Length byte should length of what follows");
    length = length < buflength ? length : buflength;
    let rheader = buf[2];
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(rheader === 2, "Integer byte for r should be 0x02");
    let rlength = buf[3];
    let rbuf = buf.subarray(4, 4 + rlength);
    let r = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(rbuf);
    let rneg = buf[4] === 0 ? true : false;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(rlength === rbuf.length, "Length of r incorrect");
    let sheader = buf[4 + rlength + 0];
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(sheader === 2, "Integer byte for s should be 0x02");
    let slength = buf[4 + rlength + 1];
    let sbuf = buf.subarray(4 + rlength + 2, 4 + rlength + 2 + slength);
    let s = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(sbuf);
    let sneg = buf[4 + rlength + 2 + 2] === 0 ? true : false;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(slength === sbuf.length, "Length of s incorrect");
    let sumlength = 4 + rlength + 2 + slength;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(length === sumlength - 2, "Length of signature incorrect");
    let obj = {
      header,
      length,
      rheader,
      rlength,
      rneg,
      rbuf,
      r,
      sheader,
      slength,
      sneg,
      sbuf,
      s
    };
    return obj;
  }
  /**
  * ECDSA format. used for sign messages
  */
  toCompact(i, compressed) {
    i = typeof i === "number" ? i : this.i;
    compressed = typeof compressed === "boolean" ? compressed : this.compressed;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(i === 0 || i === 1 || i === 2 || i === 3, "i must be equal to 0, 1, 2, or 3");
    let val = i + 27 + 4;
    if (compressed === false) val = val - 4;
    let b1 = Buffer$1.from([
      val
    ]);
    let b2 = this.r.toBuffer({
      size: 32
    });
    let b3 = this.s.toBuffer({
      size: 32
    });
    return Buffer$1.concat([
      b1,
      b2,
      b3
    ]);
  }
  static fromCompact(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "Argument is expected to be a Buffer");
    let compressed = true;
    let i = buf.subarray(0, 1)[0] - 27 - 4;
    if (i < 0) {
      compressed = false;
      i = i + 4;
    }
    let b2 = buf.subarray(1, 33);
    let b3 = buf.subarray(33, 65);
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(i === 0 || i === 1 || i === 2 || i === 3, "i must be 0, 1, 2, or 3");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(b2.length === 32, "r must be 32 bytes");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(b3.length === 32, "s must be 32 bytes");
    return new $369a157b63fbc3fd$export$2e2bcd8739ae039({
      r: $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(b2),
      s: $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(b3),
      i,
      compressed
    });
  }
}
class $2a1cae3adbd93346$export$2e2bcd8739ae039 {
  constructor(obj) {
    if (obj) this.set(obj);
  }
  set(obj) {
    this.hashbuf = obj.hashbuf || this.hashbuf;
    this.endian = obj.endian || this.endian;
    this.privkey = obj.privkey || this.privkey;
    this.pubkey = obj.pubkey || (this.privkey ? this.privkey.publicKey : this.pubkey);
    this.sig = obj.sig || this.sig;
    this.verified = obj.verified || this.verified;
    return this;
  }
  sign() {
    let hashbuf = this.hashbuf;
    let privkey = this.privkey;
    let d = privkey.bn;
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(!isNil(hashbuf) && !isNil(privkey) && !isNil(d), "invalid parameters");
    $e44f707fde477092$export$2e2bcd8739ae039.validateState($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(hashbuf) && hashbuf.length === 32, "hashbuf must be a 32 byte buffer");
    let e = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(hashbuf, this.endian ? {
      endian: this.endian
    } : void 0);
    let obj = this._findSignature(d, e);
    obj.compressed = this.pubkey.compressed;
    this.sig = new $369a157b63fbc3fd$export$2e2bcd8739ae039(obj);
    return this;
  }
  verify() {
    this.verified = !this.sigError();
    return this;
  }
  toPublicKey() {
    return this.privkey.toPublicKey();
  }
  privkey2pubkey() {
    this.pubkey = this.privkey.toPublicKey();
  }
}
const $ba7e1a38972b2d09$var$EC = $hgUW1$elliptic.ec;
class $ba7e1a38972b2d09$export$2e2bcd8739ae039 {
  static {
    this.ec = new $ba7e1a38972b2d09$var$EC("secp256k1").curve;
  }
  static {
    this._g = new $ba7e1a38972b2d09$export$2e2bcd8739ae039(this.ec.g);
  }
  constructor(point, skipValidation = false) {
    this.ecPoint = point;
    if (!skipValidation) this.validate();
  }
  /**
  * Will return the X coordinate of the Point
  *
  * @returns A BN instance of the X coordinate
  */
  getX() {
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(this.ecPoint.getX().toArray());
  }
  /**
  * Will return the Y coordinate of the Point
  *
  * @returns A BN instance of the Y coordinate
  */
  getY() {
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(this.ecPoint.getY().toArray());
  }
  add(p) {
    return new $ba7e1a38972b2d09$export$2e2bcd8739ae039(this.ecPoint.add(p.ecPoint), true);
  }
  mul(k) {
    let p = this.ecPoint.mul(k);
    return new $ba7e1a38972b2d09$export$2e2bcd8739ae039(p, true);
  }
  mulAdd(k1, p2, k2) {
    let p = this.ecPoint.mulAdd(k1, p2.ecPoint, k2);
    return new $ba7e1a38972b2d09$export$2e2bcd8739ae039(p, true);
  }
  eq(p) {
    return this.ecPoint.eq(p.ecPoint);
  }
  /**
  * Will determine if the point is valid
  *
  * @see {@link https://www.iacr.org/archive/pkc2003/25670211/25670211.pdf}
  * @throws A validation error if exists
  * @returns An instance of the same Point
  */
  validate() {
    if (this.ecPoint.isInfinity()) throw new Error("Point cannot be equal to Infinity");
    let p2;
    try {
      p2 = $ba7e1a38972b2d09$export$2e2bcd8739ae039.ec.pointFromX(this.getX(), this.getY().isOdd());
    } catch {
      throw new Error("Point does not lie on the curve");
    }
    if (p2.y.cmp(this.ecPoint.y) !== 0) throw new Error("Invalid y value for curve.");
    if (!this.ecPoint.mul($ba7e1a38972b2d09$export$2e2bcd8739ae039.getN()).isInfinity()) throw new Error("Point times N must be infinity");
    return this;
  }
  hasSquare() {
    return !this.ecPoint.isInfinity() && $ba7e1a38972b2d09$export$2e2bcd8739ae039.isSquare(this.getY());
  }
  static isSquare(x) {
    let p = new $5aa97aebe18a7924$export$2e2bcd8739ae039("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", "hex");
    let x0 = new $5aa97aebe18a7924$export$2e2bcd8739ae039(x);
    let base2 = x0.toRed($5aa97aebe18a7924$export$2e2bcd8739ae039.red(p));
    let res = base2.redPow(p.sub($5aa97aebe18a7924$export$2e2bcd8739ae039.One).div(new $5aa97aebe18a7924$export$2e2bcd8739ae039(2))).fromRed();
    return res.eq(new $5aa97aebe18a7924$export$2e2bcd8739ae039(1));
  }
  /**
  * Instantiate a valid secp256k1 Point from the X and Y coordinates.
  *
  * @param x - The X coordinate
  * @param y - The Y coordinate
  * @see {@link https://github.com/indutny/elliptic}
  * @throws A validation error if exists
  */
  static ecPoint(x, y, isRed) {
    return new $ba7e1a38972b2d09$export$2e2bcd8739ae039(this.ec.point(x, y, isRed));
  }
  /**
  *
  * Instantiate a valid secp256k1 Point from only the X coordinate
  * 
  * @param odd - If the Y coordinate is odd
  * @param x - The X coordinate
  * @throws A validation error if exists
  */
  static ecPointFromX(odd, x) {
    let point;
    try {
      point = this.ec.pointFromX(x, odd);
    } catch {
      throw new Error("Invalid X");
    }
    return new $ba7e1a38972b2d09$export$2e2bcd8739ae039(point);
  }
  /**
  *
  * Will return a secp256k1 ECDSA base point.
  *
  * @see {@link https://en.bitcoin.it/wiki/Secp256k1}
  * @returns An instance of the base point.
  */
  static getG() {
    return this._g;
  }
  /**
  *
  * Will return the max of range of valid private keys as governed by the secp256k1 ECDSA standard.
  *
  * @see {@link https://en.bitcoin.it/wiki/Private_key#Range_of_valid_ECDSA_private_keys}
  * @returns A BN instance of the number of points on the curve
  */
  static getN() {
    return new $5aa97aebe18a7924$export$2e2bcd8739ae039(this.ec.n.toArray());
  }
  static pointToCompressed(point) {
    let xbuf = point.getX().toBuffer({
      size: 32
    });
    let ybuf = point.getY().toBuffer({
      size: 32
    });
    let odd = ybuf[ybuf.length - 1] % 2;
    let prefix = Buffer$1.from(odd ? [
      3
    ] : [
      2
    ]);
    return Buffer$1.concat([
      prefix,
      xbuf
    ]);
  }
}
class $246eb589bb078d6d$export$2e2bcd8739ae039 {
  /**
  * @param data - The pubkey data
  */
  constructor(data) {
    this.toObject = this.toJSON;
    this.toDER = this.toBuffer;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isNil(data), "First argument is required, please include public key data.");
    if (data instanceof $246eb589bb078d6d$export$2e2bcd8739ae039)
      return data;
    if ($246eb589bb078d6d$export$2e2bcd8739ae039._isPublicKeyData(data)) {
      data.point.validate();
      this.point = data.point;
      this.compressed = isUndefined(data.compressed) || data.compressed;
      this.network = data.network || $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork;
    } else throw new TypeError("First argument is an unrecognized data format.");
  }
  /**
  * @returns A plain object of the PublicKey
  */
  toJSON() {
    return {
      x: this.point.getX().toString("hex", 2),
      y: this.point.getY().toString("hex", 2),
      compressed: this.compressed,
      network: this.network.toString()
    };
  }
  /**
  * Will output the PublicKey to a DER Buffer
  *
  * @returns  A DER hex encoded buffer
  */
  toBuffer() {
    let x = this.point.getX();
    let y = this.point.getY();
    let xbuf = x.toBuffer({
      size: 32
    });
    let ybuf = y.toBuffer({
      size: 32
    });
    let prefix;
    if (!this.compressed) {
      prefix = Buffer$1.from([
        4
      ]);
      return Buffer$1.concat([
        prefix,
        xbuf,
        ybuf
      ]);
    } else {
      let odd = ybuf[ybuf.length - 1] % 2;
      if (odd) prefix = Buffer$1.from([
        3
      ]);
      else prefix = Buffer$1.from([
        2
      ]);
      return Buffer$1.concat([
        prefix,
        xbuf
      ]);
    }
  }
  /**
  * Will output the PublicKey to a DER encoded hex string
  *
  * @returns A DER hex encoded string
  */
  toString() {
    return this.toBuffer().toString("hex");
  }
  /**
  * Will return a string formatted for the console
  *
  * @returns Public key string inspection
  */
  inspect() {
    return "<PublicKey: " + this.toString() + (this.compressed ? "" : ", uncompressed") + ">";
  }
  /**
  * Instantiate a PublicKey from various formats
  * 
  * @param data The encoded data in various formats
  * @param compressed If the public key is compressed
  * @param network The key network
  * @returns New PublicKey instance
  */
  static from(data, compressed, network) {
    if (data instanceof $246eb589bb078d6d$export$2e2bcd8739ae039) return data;
    else if (data instanceof $ba7e1a38972b2d09$export$2e2bcd8739ae039) return this.fromPoint(data, compressed, network);
    else if (this._isPublicKeyDto(data)) return this.fromObject(data);
    else if (this._isPublicKeyData(data)) return new $246eb589bb078d6d$export$2e2bcd8739ae039(data);
    else if (this._isPrivateKeyData(data)) return this.fromPrivateKey(data);
    else if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(data)) return this.fromBuffer(data, true, network);
    else if ($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(data)) return this.fromString(data, "hex", network);
    else throw new TypeError("First argument is an unrecognized data format.");
  }
  static {
    this.fromDER = this.fromBuffer;
  }
  static {
    this.fromObject = this.fromJSON;
  }
  /**
  * Instantiate a PublicKey from a Buffer
  * 
  * @param buf - A DER hex buffer
  * @param strict - if set to false, will loosen some conditions
  * @param network - the network of the key
  * @returns A new valid instance of PublicKey
  */
  static fromBuffer(buf, strict, network) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "Must be a hex buffer of DER encoded public key");
    let info = $246eb589bb078d6d$export$2e2bcd8739ae039._transformDER(buf, strict);
    return new $246eb589bb078d6d$export$2e2bcd8739ae039({
      point: info.point,
      compressed: info.compressed,
      network
    });
  }
  /**
  * Instantiate a PublicKey from a Point
  *
  * @param point - A Point instance
  * @param compressed - whether to store this public key as compressed format
  * @param network - the network of the key
  * @returns A new valid instance of PublicKey
  */
  static fromPoint(point, compressed, network) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(point instanceof $ba7e1a38972b2d09$export$2e2bcd8739ae039, "First argument must be an instance of Point.");
    return new $246eb589bb078d6d$export$2e2bcd8739ae039({
      point,
      compressed,
      network
    });
  }
  /**
  * Instantiate a PublicKey from a DER hex encoded string
  *
  * @param str - A DER hex string
  * @param encoding - The type of string encoding
  * @param network - the network of the key
  * @returns A new valid instance of PublicKey
  */
  static fromString(str, encoding, network) {
    let buf = Buffer$1.from(str, encoding || "hex");
    let info = $246eb589bb078d6d$export$2e2bcd8739ae039._transformDER(buf);
    return new $246eb589bb078d6d$export$2e2bcd8739ae039({
      point: info.point,
      compressed: info.compressed,
      network
    });
  }
  /**
  * Instantiate a PublicKey from PrivateKey data
  *
  * @param data - Object contains data of PrivateKey
  * @returns A new valid instance of PublicKey
  */
  static fromPrivateKey(data) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(this._isPrivateKeyData(data), "data", "Must be data of PrivateKey");
    let point = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getG().mul(data.bn);
    return new $246eb589bb078d6d$export$2e2bcd8739ae039({
      point,
      compressed: data.compressed,
      network: data.network
    });
  }
  static fromJSON(data) {
    let info = $246eb589bb078d6d$export$2e2bcd8739ae039._transformObject(data);
    return new $246eb589bb078d6d$export$2e2bcd8739ae039(info);
  }
  /**
  * Check if there would be any errors when initializing a PublicKey
  *
  * @param data - The encoded data in various formats
  * @returns An error if exists
  */
  static getValidationError(data) {
    try {
      this.from(data);
    } catch (e) {
      return e;
    }
    return void 0;
  }
  /**
  * Check if the parameters are valid
  *
  * @param data - The encoded data in various formats
  * @returns true If the public key would be valid
  */
  static isValid(data) {
    return !$246eb589bb078d6d$export$2e2bcd8739ae039.getValidationError(data);
  }
  static _isPublicKeyData(data) {
    return isObject$1(data) && "point" in data && data.point instanceof $ba7e1a38972b2d09$export$2e2bcd8739ae039;
  }
  static _isPublicKeyDto(data) {
    return isObject$1(data) && "x" in data && "y" in data;
  }
  static _isPrivateKeyData(data) {
    return isObject$1(data) && "bn" in data && "network" in data;
  }
  /**
  * Internal function to transform DER into a public key point
  *
  * @param buf - An hex encoded buffer
  * @param strict - if set to false, will loosen some conditions
  * @returns An object with keys: point and compressed
  */
  static _transformDER(buf, strict) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "Must be a hex buffer of DER encoded public key");
    strict = isUndefined(strict) ? true : strict;
    if (buf[0] === 4 || !strict && (buf[0] === 6 || buf[0] === 7)) {
      let xbuf = buf.subarray(1, 33);
      let ybuf = buf.subarray(33, 65);
      if (xbuf.length !== 32 || ybuf.length !== 32 || buf.length !== 65) throw new TypeError("Length of x and y must be 32 bytes");
      let x = new $5aa97aebe18a7924$export$2e2bcd8739ae039(xbuf);
      let y = new $5aa97aebe18a7924$export$2e2bcd8739ae039(ybuf);
      return {
        point: $ba7e1a38972b2d09$export$2e2bcd8739ae039.ecPoint(x, y),
        compressed: false
      };
    } else if (buf[0] === 3) {
      let xbuf = buf.subarray(1);
      let x = new $5aa97aebe18a7924$export$2e2bcd8739ae039(xbuf);
      return {
        point: $ba7e1a38972b2d09$export$2e2bcd8739ae039.ecPointFromX(true, x),
        compressed: true
      };
    } else if (buf[0] === 2) {
      let xbuf = buf.subarray(1);
      let x = new $5aa97aebe18a7924$export$2e2bcd8739ae039(xbuf);
      return {
        point: $ba7e1a38972b2d09$export$2e2bcd8739ae039.ecPointFromX(false, x),
        compressed: true
      };
    } else throw new TypeError("Invalid DER format public key");
  }
  /**
  * Internal function to transform a JSON into a public key point
  */
  static _transformObject(json) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(json.x), "x", "must be a hex string");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(json.y), "y", "must be a hex string");
    let x = new $5aa97aebe18a7924$export$2e2bcd8739ae039(json.x, "hex");
    let y = new $5aa97aebe18a7924$export$2e2bcd8739ae039(json.y, "hex");
    let point = $ba7e1a38972b2d09$export$2e2bcd8739ae039.ecPoint(x, y);
    return {
      point,
      compressed: json.compressed,
      network: $a89918d61ea4dca0$export$f09b1917886389c3.get(json.network)
    };
  }
}
class $1ef65db4b26d2b16$export$2e2bcd8739ae039 extends $2a1cae3adbd93346$export$2e2bcd8739ae039 {
  set(obj) {
    this.k = obj.k || this.k;
    return super.set(obj);
  }
  sigError() {
    if (!$9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(this.hashbuf) || this.hashbuf.length !== 32) return "hashbuf must be a 32 byte buffer";
    let r = this.sig.r;
    let s = this.sig.s;
    if (!(r.gt($5aa97aebe18a7924$export$2e2bcd8739ae039.Zero) && r.lt($ba7e1a38972b2d09$export$2e2bcd8739ae039.getN())) || !(s.gt($5aa97aebe18a7924$export$2e2bcd8739ae039.Zero) && s.lt($ba7e1a38972b2d09$export$2e2bcd8739ae039.getN()))) return "r and s not in range";
    let e = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(this.hashbuf, this.endian ? {
      endian: this.endian
    } : void 0);
    let n = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getN();
    let sinv = s.invm(n);
    let u1 = sinv.mul(e).umod(n);
    let u2 = sinv.mul(r).umod(n);
    let p = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getG().mulAdd(new $5aa97aebe18a7924$export$2e2bcd8739ae039(u1), this.pubkey.point, new $5aa97aebe18a7924$export$2e2bcd8739ae039(u2));
    if (p.ecPoint.isInfinity()) return "p is infinity";
    if (p.getX().umod(n).cmp(r) !== 0) return "Invalid signature";
    else return false;
  }
  _findSignature(d, e) {
    let N = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getN();
    let G = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getG();
    let badrs = 0;
    let k, Q, r, s;
    do {
      if (!this.k || badrs > 0) this.deterministicK(badrs);
      badrs++;
      k = this.k;
      Q = G.mul(k);
      r = Q.ecPoint.x.umod(N);
      s = k.invm(N).mul(e.add(d.mul(r))).umod(N);
    } while (r.cmp($5aa97aebe18a7924$export$2e2bcd8739ae039.Zero) <= 0 || s.cmp($5aa97aebe18a7924$export$2e2bcd8739ae039.Zero) <= 0);
    s = $1ef65db4b26d2b16$export$2e2bcd8739ae039.toLowS(new $5aa97aebe18a7924$export$2e2bcd8739ae039(s));
    return {
      s,
      r: new $5aa97aebe18a7924$export$2e2bcd8739ae039(r)
    };
  }
  static toLowS(s) {
    if (s.gt($5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(Buffer$1.from("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", "hex")))) s = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getN().sub(s);
    return s;
  }
  calcI() {
    for (let i = 0; i < 4; i++) {
      this.sig.i = i;
      let Qprime;
      try {
        Qprime = this.toPublicKey();
      } catch {
        continue;
      }
      if (Qprime.point.eq(this.pubkey.point)) {
        this.sig.compressed = this.pubkey.compressed;
        return this;
      }
    }
    this.sig.i = void 0;
    throw new Error(`Unable to find valid recovery factor`);
  }
  randomK() {
    let N = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getN();
    let k;
    do
      k = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer($9f918c10ad4fef51$export$2e2bcd8739ae039.getRandomBuffer(32));
    while (!(k.lt(N) && k.gt($5aa97aebe18a7924$export$2e2bcd8739ae039.Zero)));
    this.k = k;
    return this;
  }
  // https://tools.ietf.org/html/rfc6979#section-3.2
  deterministicK(badrs) {
    if (isUndefined(badrs)) badrs = 0;
    let v = Buffer$1.alloc(32);
    v.fill(1);
    let k = Buffer$1.alloc(32);
    k.fill(0);
    let x = this.privkey.bn.toBuffer({
      size: 32
    });
    let hashbuf = this.endian === "little" ? $9f918c10ad4fef51$export$2e2bcd8739ae039.reverse(this.hashbuf) : this.hashbuf;
    k = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(Buffer$1.concat([
      v,
      Buffer$1.from([
        0
      ]),
      x,
      hashbuf
    ]), k);
    v = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(v, k);
    k = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(Buffer$1.concat([
      v,
      Buffer$1.from([
        1
      ]),
      x,
      hashbuf
    ]), k);
    v = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(v, k);
    v = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(v, k);
    let T = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(v);
    let N = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getN();
    for (let i = 0; i < badrs || !(T.lt(N) && T.gt($5aa97aebe18a7924$export$2e2bcd8739ae039.Zero)); i++) {
      k = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(Buffer$1.concat([
        v,
        Buffer$1.from([
          0
        ])
      ]), k);
      v = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(v, k);
      v = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(v, k);
      T = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(v);
    }
    this.k = T;
    return this;
  }
  signRandomK() {
    this.randomK();
    return this.sign();
  }
  toString() {
    let obj = {};
    if (this.hashbuf) obj.hashbuf = this.hashbuf.toString("hex");
    if (this.privkey) obj.privkey = this.privkey.toString();
    if (this.pubkey) obj.pubkey = this.pubkey.toString();
    if (this.sig) obj.sig = this.sig.toString();
    if (this.k) obj.k = this.k.toString();
    return JSON.stringify(obj);
  }
  // Information about public key recovery:
  // https://bitcointalk.org/index.php?topic=6430.0
  // http://stackoverflow.com/questions/19665491/how-do-i-get-an-ecdsa-public-key-from-just-a-bitcoin-signature-sec1-4-1-6-k
  toPublicKey() {
    let i = this.sig.i;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(i === 0 || i === 1 || i === 2 || i === 3, "i must be equal to 0, 1, 2, or 3");
    let e = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(this.hashbuf);
    let r = this.sig.r;
    let s = this.sig.s;
    let isYOdd = i & 1;
    let isSecondKey = i >> 1;
    let n = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getN();
    let G = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getG();
    let x = isSecondKey ? r.add(n) : r;
    let R = $ba7e1a38972b2d09$export$2e2bcd8739ae039.ecPointFromX(!!isYOdd, x);
    let nR = R.mul(n);
    if (!nR.ecPoint.isInfinity()) throw new Error("nR is not a valid curve point");
    let eNeg = e.neg().umod(n);
    let rInv = r.invm(n);
    let Q = R.mul(s).add(G.mul(new $5aa97aebe18a7924$export$2e2bcd8739ae039(eNeg))).mul(new $5aa97aebe18a7924$export$2e2bcd8739ae039(rInv));
    let pubkey = $246eb589bb078d6d$export$2e2bcd8739ae039.fromPoint(Q, this.sig.compressed);
    return pubkey;
  }
  static fromString(str) {
    let obj = JSON.parse(str);
    return new $1ef65db4b26d2b16$export$2e2bcd8739ae039(obj);
  }
  static sign(hashbuf, privkey, endian) {
    return new $1ef65db4b26d2b16$export$2e2bcd8739ae039({
      hashbuf,
      endian,
      privkey
    }).sign().sig;
  }
  static verify(hashbuf, sig, pubkey, endian) {
    return new $1ef65db4b26d2b16$export$2e2bcd8739ae039({
      hashbuf,
      endian,
      sig,
      pubkey
    }).verify().verified;
  }
}
class $1739481af0c86d04$export$2e2bcd8739ae039 extends $2a1cae3adbd93346$export$2e2bcd8739ae039 {
  sigError() {
    if (!$9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(this.hashbuf) || this.hashbuf.length !== 32) return "hashbuf must be a 32 byte buffer";
    let sigLength = $1739481af0c86d04$export$2e2bcd8739ae039.getProperSizeBuffer(this.sig.r).length + $1739481af0c86d04$export$2e2bcd8739ae039.getProperSizeBuffer(this.sig.s).length;
    if (!(sigLength === 64 || sigLength === 65)) return "signature must be a 64 byte or 65 byte array";
    let hashbuf = this.endian === "little" ? $9f918c10ad4fef51$export$2e2bcd8739ae039.reverse(this.hashbuf) : this.hashbuf;
    let P = this.pubkey.point;
    let G = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getG();
    if (P.ecPoint.isInfinity()) return true;
    let r = this.sig.r;
    let s = this.sig.s;
    let p = new $5aa97aebe18a7924$export$2e2bcd8739ae039("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", "hex");
    let n = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getN();
    if (r.gte(p) || s.gte(n))
      return true;
    let Br = $1739481af0c86d04$export$2e2bcd8739ae039.getProperSizeBuffer(this.sig.r);
    let Bp = $ba7e1a38972b2d09$export$2e2bcd8739ae039.pointToCompressed(P);
    let hash = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256(Buffer$1.concat([
      Br,
      Bp,
      hashbuf
    ]));
    let e = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(hash, {
      endian: "big"
    }).umod(n);
    let sG = G.mul(s);
    let eP = P.mul(n.sub(e));
    let R = sG.add(eP);
    if (R.ecPoint.isInfinity() || !R.hasSquare() || !R.getX().eq(r)) return true;
    return false;
  }
  /**
  * RFC6979 deterministic nonce generation used from https://reviews.bitcoinabc.org/D2501
  * 
  * @param privkeybuf 
  * @param msgbuf 
  * @return BN nonce
  */
  nonceFunctionRFC6979(privkeybuf, msgbuf) {
    let V = Buffer$1.from("0101010101010101010101010101010101010101010101010101010101010101", "hex");
    let K = Buffer$1.from("0000000000000000000000000000000000000000000000000000000000000000", "hex");
    let blob = Buffer$1.concat([
      privkeybuf,
      msgbuf,
      Buffer$1.from("", "ascii"),
      Buffer$1.from("Schnorr+SHA256  ", "ascii")
    ]);
    K = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(Buffer$1.concat([
      V,
      Buffer$1.from("00", "hex"),
      blob
    ]), K);
    V = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(V, K);
    K = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(Buffer$1.concat([
      V,
      Buffer$1.from("01", "hex"),
      blob
    ]), K);
    V = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(V, K);
    let k = new $5aa97aebe18a7924$export$2e2bcd8739ae039(0);
    let T;
    while (true) {
      V = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(V, K);
      T = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(V);
      k = T;
      $e44f707fde477092$export$2e2bcd8739ae039.validateState(V.length >= 32, "V length should be >= 32");
      if (k.gt(new $5aa97aebe18a7924$export$2e2bcd8739ae039(0)) && k.lt($ba7e1a38972b2d09$export$2e2bcd8739ae039.getN())) break;
      K = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(Buffer$1.concat([
        V,
        Buffer$1.from("00", "hex")
      ]), K);
      V = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256hmac(V, K);
    }
    return k;
  }
  /**
  * @remarks
  * Important references for schnorr implementation {@link https://spec.nexa.org/forks/2019-05-15-schnorr/}
  * 
  * @param d the private key
  * @param e the message to be signed
  */
  _findSignature(d, e) {
    let n = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getN();
    let G = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getG();
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(!d.lte(new $5aa97aebe18a7924$export$2e2bcd8739ae039(0)), "privkey out of field of curve");
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(!d.gte(n), "privkey out of field of curve");
    let k = this.nonceFunctionRFC6979(d.toBuffer({
      size: 32
    }), e.toBuffer({
      size: 32
    }));
    let P = G.mul(d);
    let R = G.mul(k);
    if (R.hasSquare()) ;
    else k = n.sub(k);
    let r = R.getX();
    let e0 = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer($62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256(Buffer$1.concat([
      $1739481af0c86d04$export$2e2bcd8739ae039.getProperSizeBuffer(r),
      $ba7e1a38972b2d09$export$2e2bcd8739ae039.pointToCompressed(P),
      e.toBuffer({
        size: 32
      })
    ])));
    let s = e0.mul(d).add(k).mod(n);
    return {
      r,
      s
    };
  }
  /**
  * Function written to ensure s or r parts of signature is at least 32 bytes, when converting 
  * from a BN to type Buffer.
  * The BN type naturally cuts off leading zeros, e.g.
  * <BN: 4f92d8094f710bc11b93935ac157730dda26c5c2a856650dbd8ebcd730d2d4> 31 bytes
  * Buffer <00 4f 92 d8 09 4f 71 0b c1 1b 93 93 5a c1 57 73 0d da 26 c5 c2 a8 56 65 0d bd 8e bc d7 30 d2 d4> 32 bytes
  * Both types are equal, however Schnorr signatures must be a minimum of 64 bytes.
  * In a previous implementation of this schnorr module, was resulting in 63 byte signatures. 
  * (Although it would have been verified, it's proper to ensure the min requirement)
  * 
  * @param buf the r or s signature part
  */
  static getProperSizeBuffer(buf) {
    if (buf.toBuffer().length < 32) return buf.toBuffer({
      size: 32
    });
    return buf.toBuffer();
  }
  static sign(hashbuf, privkey, endian) {
    return new $1739481af0c86d04$export$2e2bcd8739ae039({
      hashbuf,
      endian,
      privkey
    }).sign().sig;
  }
  static verify(hashbuf, sig, pubkey, endian) {
    return new $1739481af0c86d04$export$2e2bcd8739ae039({
      hashbuf,
      endian,
      sig,
      pubkey
    }).verify().verified;
  }
}
class $5d1fb851ba849ee0$export$2e2bcd8739ae039 {
  static {
    this.ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".split("");
  }
  constructor(obj) {
    if (Buffer$1.isBuffer(obj)) {
      let buf = obj;
      this.fromBuffer(buf);
    } else if (typeof obj === "string") {
      let str = obj;
      this.fromString(str);
    } else if (obj) this.set(obj);
  }
  toBuffer() {
    return this.buf;
  }
  toString() {
    return this.buf ? $5d1fb851ba849ee0$export$2e2bcd8739ae039.encode(this.buf) : "";
  }
  fromBuffer(buf) {
    this.buf = buf;
    return this;
  }
  fromString(str) {
    let buf = $5d1fb851ba849ee0$export$2e2bcd8739ae039.decode(str);
    this.buf = buf;
    return this;
  }
  set(obj) {
    this.buf = obj.buf || this.buf || void 0;
    return this;
  }
  static encode(buf) {
    if (!Buffer$1.isBuffer(buf)) throw new Error("Input should be a buffer");
    return $hgUW1$bs58.encode(buf);
  }
  static decode(str) {
    if (typeof str !== "string") throw new Error("Input should be a string");
    return Buffer$1.from($hgUW1$bs58.decode(str));
  }
  static validCharacters(chars) {
    if (Buffer$1.isBuffer(chars)) chars = chars.toString();
    return chars.split("").every((char) => $5d1fb851ba849ee0$export$2e2bcd8739ae039.ALPHABET.includes(char));
  }
}
class $7daa49d6586b1e1a$export$2e2bcd8739ae039 {
  constructor(obj) {
    if (Buffer$1.isBuffer(obj)) {
      let buf = obj;
      this.fromBuffer(buf);
    } else if (typeof obj === "string") {
      let str = obj;
      this.fromString(str);
    } else if (obj) this.set(obj);
  }
  static validChecksum(data, checksum) {
    if (isString(data)) data = Buffer$1.from($5d1fb851ba849ee0$export$2e2bcd8739ae039.decode(data));
    if (isString(checksum)) checksum = Buffer$1.from($5d1fb851ba849ee0$export$2e2bcd8739ae039.decode(checksum));
    if (!checksum) {
      checksum = data.subarray(-4);
      data = data.subarray(0, -4);
    }
    return $7daa49d6586b1e1a$export$2e2bcd8739ae039.checksum(data).toString("hex") === checksum.toString("hex");
  }
  static decode(s) {
    if (typeof s !== "string") throw new Error("Input must be a string");
    let buf = Buffer$1.from($5d1fb851ba849ee0$export$2e2bcd8739ae039.decode(s));
    if (buf.length < 4) throw new Error("Input string too short");
    let data = buf.subarray(0, -4);
    let csum = buf.subarray(-4);
    let hash = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(data);
    let hash4 = hash.subarray(0, 4);
    if (csum.toString("hex") !== hash4.toString("hex")) throw new Error("Checksum mismatch");
    return data;
  }
  static checksum(buffer) {
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buffer).subarray(0, 4);
  }
  static encode(buf) {
    if (!Buffer$1.isBuffer(buf)) throw new Error("Input must be a buffer");
    let checkedBuf = Buffer$1.alloc(buf.length + 4);
    let hash = $7daa49d6586b1e1a$export$2e2bcd8739ae039.checksum(buf);
    buf.copy(checkedBuf);
    hash.copy(checkedBuf, buf.length);
    return $5d1fb851ba849ee0$export$2e2bcd8739ae039.encode(checkedBuf);
  }
  toBuffer() {
    return this.buf;
  }
  toString() {
    return this.buf ? $7daa49d6586b1e1a$export$2e2bcd8739ae039.encode(this.buf) : "";
  }
  fromBuffer(buf) {
    this.buf = buf;
    return this;
  }
  fromString(str) {
    let buf = $7daa49d6586b1e1a$export$2e2bcd8739ae039.decode(str);
    this.buf = buf;
    return this;
  }
  set(obj) {
    this.buf = obj.buf || this.buf || void 0;
    return this;
  }
}
class $9a13d4ba0015a72e$export$2e2bcd8739ae039 {
  static {
    this.CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  }
  static {
    this.CHARSET_INVERSE_INDEX = {
      "q": 0,
      "p": 1,
      "z": 2,
      "r": 3,
      "y": 4,
      "9": 5,
      "x": 6,
      "8": 7,
      "g": 8,
      "f": 9,
      "2": 10,
      "t": 11,
      "v": 12,
      "d": 13,
      "w": 14,
      "0": 15,
      "s": 16,
      "3": 17,
      "j": 18,
      "n": 19,
      "5": 20,
      "4": 21,
      "k": 22,
      "h": 23,
      "c": 24,
      "e": 25,
      "6": 26,
      "m": 27,
      "u": 28,
      "a": 29,
      "7": 30,
      "l": 31
    };
  }
  /***
  * Encodes the given array of 5-bit integers as a base32-encoded string.
  *
  * @param data Array of integers between 0 and 31 inclusive.
  */
  static encode(data) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(data instanceof Array, "Must be Array");
    let base32 = "";
    data.forEach((value) => {
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(0 <= value && value < 32, "value " + value);
      base32 += this.CHARSET[value];
    });
    return base32;
  }
  /***
  * Decodes the given base32-encoded string into an array of 5-bit integers.
  *
  * @param base32 
  */
  static decode(base32) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(typeof base32 === "string", "Must be base32-encoded string");
    let data = [];
    for (let value of base32) {
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(value in this.CHARSET_INVERSE_INDEX, "value " + value);
      data.push(this.CHARSET_INVERSE_INDEX[value]);
    }
    return data;
  }
}
var $c889a5b1bdeeb100$export$189c6ba3eaa96ac2 = /* @__PURE__ */ (function(AddressType) {
  AddressType["PayToPublicKeyHash"] = "P2PKH";
  AddressType["PayToScriptTemplate"] = "P2ST";
  AddressType["GroupIdAddress"] = "GROUP";
  return AddressType;
})({});
class $c889a5b1bdeeb100$export$2e2bcd8739ae039 {
  static {
    this.VALID_PREFIXES = [
      "nexa",
      "nexatest"
    ];
  }
  /** @see encodeAddress */
  static encode(prefix, type, data) {
    return this.encodeAddress({
      prefix,
      type,
      data
    });
  }
  /**
  * Encodes a hash from a given type into a Nexa address with the given prefix.
  *
  * @param address Object contains Network prefix (E.g.: 'nexa'), Type of address to generate and data to encode.
  */
  static encodeAddress(address) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(typeof address.prefix === "string" && this.isValidPrefix(address.prefix), "Invalid prefix: " + address.prefix + ".");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(typeof address.type === "string", "Invalid type: " + address.type + ".");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(address.data), "Invalid data: " + address.data + ".");
    let eight0 = [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ];
    let prefixData = this.prefixToArray(address.prefix).concat([
      0
    ]);
    let versionByte = this.getTypeBits(address.type);
    let payloadData = this.convertBits(Buffer$1.concat([
      Buffer$1.from([
        versionByte
      ]),
      address.data
    ]), 8, 5);
    let checksumData = prefixData.concat(payloadData).concat(eight0);
    let payload = payloadData.concat(this.checksumToArray(this.polymod(checksumData)));
    return address.prefix + ":" + $9a13d4ba0015a72e$export$2e2bcd8739ae039.encode(payload);
  }
  /**
  * Decodes the given address into its constituting prefix, type and data. See {@link encodeAddress}.
  *
  * @param {string} address Address to decode. E.g.: 'nexa:qpm2qsznhks23z7629mms6s4cwef74vcwvgpsey0xy'.
  */
  static decode(address) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(typeof address === "string" && this.hasSingleCase(address), "Invalid address: " + address + ".");
    let pieces = address.toLowerCase().split(":");
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(pieces.length === 2, "Missing prefix: " + address + ".");
    let prefix = pieces[0];
    let payload = $9a13d4ba0015a72e$export$2e2bcd8739ae039.decode(pieces[1]);
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.validChecksum(prefix, payload), "Invalid checksum: " + address + ".");
    let convertedBits = this.convertBits(payload.slice(0, -8), 5, 8, true);
    let versionByte = convertedBits.shift();
    let hash = convertedBits;
    let type = this.getType(versionByte);
    return {
      prefix,
      type,
      data: Buffer$1.from(hash)
    };
  }
  /**
  * Checks whether a string is a valid prefix; ie., it has a single letter case
  * and is one of the above.
  * 
  * @param prefix
  */
  static isValidPrefix(prefix) {
    return this.hasSingleCase(prefix) && this.VALID_PREFIXES.includes(prefix.toLowerCase());
  }
  /**
  * Derives an array from the given prefix to be used in the computation
  * of the address' checksum.
  *
  * @param prefix Network prefix. E.g.: 'nexa'.
  */
  static prefixToArray(prefix) {
    let result = [];
    for (let i = 0; i < prefix.length; ++i) result.push(prefix.charCodeAt(i) & 31);
    return result;
  }
  /**
  * Returns an array representation of the given checksum to be encoded
  * within the address' payload.
  *
  * @param checksum Computed checksum.
  */
  static checksumToArray(checksum) {
    let result = [];
    for (let i = 0; i < 8; ++i) {
      result.push(checksum & 31);
      checksum /= 32;
    }
    return result.reverse();
  }
  /**
  * Returns the bit representation of the given type within the version byte.
  *
  * @param type Address type. Either 'P2PKH' or 'P2SH'.
  */
  static getTypeBits(type) {
    switch (type) {
      case "P2PKH":
        return 0;
      case "P2ST":
        return 152;
      case "GROUP":
        return 88;
      default:
        throw new TypeError("Invalid type: " + type + ".");
    }
  }
  /**
  * Retrieves the address type from its bit representation within the
  * version byte.
  *
  * @param versionByte
  */
  static getType(versionByte) {
    switch (versionByte & 248) {
      case 0:
        return "P2PKH";
      case 152:
        return "P2ST";
      case 88:
        return "GROUP";
      default:
        throw new Error("Invalid address type in version byte: " + versionByte + ".");
    }
  }
  /**
  * Returns true if, and only if, the given string contains either uppercase
  * or lowercase letters, but not both.
  *
  * @param string Input string.
  */
  static hasSingleCase(string) {
    return string === string.toLowerCase() || string === string.toUpperCase();
  }
  /**
  * Verify that the payload has not been corrupted by checking that the
  * checksum is valid.
  *
  * @param prefix Network prefix. E.g.: 'nexa'.
  * @param payload Array of 5-bit integers containing the address' payload.
  */
  static validChecksum(prefix, payload) {
    let prefixData = this.prefixToArray(prefix).concat([
      0
    ]);
    return this.polymod(prefixData.concat(payload)) === 0;
  }
  /**
  * Computes a checksum from the given input data as specified for the CashAddr
  * format: https://github.com/Bitcoin-UAHF/spec/blob/master/cashaddr.md.
  *
  * @param data Array of 5-bit integers over which the checksum is to be computed.
  */
  static polymod(data) {
    let GENERATOR1 = [
      152,
      121,
      243,
      174,
      30
    ];
    let GENERATOR2 = [
      4072443489,
      3077413346,
      1046459332,
      783016616,
      1329849456
    ];
    let c0 = 0, c1 = 1, C = 0;
    for (let j = 0; j < data.length; j++) {
      C = c0 >>> 3;
      c0 &= 7;
      c0 <<= 5;
      c0 |= c1 >>> 27;
      c1 &= 134217727;
      c1 <<= 5;
      c1 ^= data[j];
      for (let i = 0; i < GENERATOR1.length; ++i) if (C & 1 << i) {
        c0 ^= GENERATOR1[i];
        c1 ^= GENERATOR2[i];
      }
    }
    c1 ^= 1;
    if (c1 < 0) {
      c1 ^= -2147483648;
      c1 += 1073741824 * 2;
    }
    return c0 * 1073741824 * 4 + c1;
  }
  /**
  * Converts an array of integers made up of `from` bits into an
  * array of integers made up of `to` bits. The output array is
  * zero-padded if necessary, unless strict mode is true.
  * Original by Pieter Wuille: https://github.com/sipa/bech32.
  *
  * @param data Array of integers made up of `from` bits.
  * @param from Length in bits of elements in the input array.
  * @param to Length in bits of elements in the output array.
  * @param strict Require the conversion to be completed without padding.
  */
  static convertBits(data, from, to, strict = false) {
    let accumulator = 0;
    let bits = 0;
    let result = [];
    let mask = (1 << to) - 1;
    for (let i = 0; i < data.length; i++) {
      let value = data[i];
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!(value < 0 || value >> from !== 0), "value " + value);
      accumulator = accumulator << from | value;
      bits += from;
      while (bits >= to) {
        bits -= to;
        result.push(accumulator >> bits & mask);
      }
    }
    if (!strict) {
      if (bits > 0) result.push(accumulator << to - bits & mask);
    } else $e44f707fde477092$export$2e2bcd8739ae039.validateState(!(bits >= from || accumulator << to - bits & mask), "Conversion requires padding but strict mode was used");
    return result;
  }
}
var $92c0719d4ab9ac45$export$393941f88fd16991 = /* @__PURE__ */ (function(Opcode) {
  Opcode[Opcode["OP_FALSE"] = 0] = "OP_FALSE";
  Opcode[Opcode["OP_0"] = 0] = "OP_0";
  Opcode[Opcode["OP_PUSHDATA1"] = 76] = "OP_PUSHDATA1";
  Opcode[Opcode["OP_PUSHDATA2"] = 77] = "OP_PUSHDATA2";
  Opcode[Opcode["OP_PUSHDATA4"] = 78] = "OP_PUSHDATA4";
  Opcode[Opcode["OP_1NEGATE"] = 79] = "OP_1NEGATE";
  Opcode[Opcode["OP_RESERVED"] = 80] = "OP_RESERVED";
  Opcode[Opcode["OP_TRUE"] = 81] = "OP_TRUE";
  Opcode[Opcode["OP_1"] = 81] = "OP_1";
  Opcode[Opcode["OP_2"] = 82] = "OP_2";
  Opcode[Opcode["OP_3"] = 83] = "OP_3";
  Opcode[Opcode["OP_4"] = 84] = "OP_4";
  Opcode[Opcode["OP_5"] = 85] = "OP_5";
  Opcode[Opcode["OP_6"] = 86] = "OP_6";
  Opcode[Opcode["OP_7"] = 87] = "OP_7";
  Opcode[Opcode["OP_8"] = 88] = "OP_8";
  Opcode[Opcode["OP_9"] = 89] = "OP_9";
  Opcode[Opcode["OP_10"] = 90] = "OP_10";
  Opcode[Opcode["OP_11"] = 91] = "OP_11";
  Opcode[Opcode["OP_12"] = 92] = "OP_12";
  Opcode[Opcode["OP_13"] = 93] = "OP_13";
  Opcode[Opcode["OP_14"] = 94] = "OP_14";
  Opcode[Opcode["OP_15"] = 95] = "OP_15";
  Opcode[Opcode["OP_16"] = 96] = "OP_16";
  Opcode[Opcode["OP_NOP"] = 97] = "OP_NOP";
  Opcode[Opcode["OP_INVALID_CONTROL1"] = 98] = "OP_INVALID_CONTROL1";
  Opcode[Opcode["OP_IF"] = 99] = "OP_IF";
  Opcode[Opcode["OP_NOTIF"] = 100] = "OP_NOTIF";
  Opcode[Opcode["OP_JUMP"] = 101] = "OP_JUMP";
  Opcode[Opcode["OP_INVALID_CONTROL2"] = 102] = "OP_INVALID_CONTROL2";
  Opcode[Opcode["OP_ELSE"] = 103] = "OP_ELSE";
  Opcode[Opcode["OP_ENDIF"] = 104] = "OP_ENDIF";
  Opcode[Opcode["OP_VERIFY"] = 105] = "OP_VERIFY";
  Opcode[Opcode["OP_RETURN"] = 106] = "OP_RETURN";
  Opcode[Opcode["OP_TOALTSTACK"] = 107] = "OP_TOALTSTACK";
  Opcode[Opcode["OP_FROMALTSTACK"] = 108] = "OP_FROMALTSTACK";
  Opcode[Opcode["OP_2DROP"] = 109] = "OP_2DROP";
  Opcode[Opcode["OP_2DUP"] = 110] = "OP_2DUP";
  Opcode[Opcode["OP_3DUP"] = 111] = "OP_3DUP";
  Opcode[Opcode["OP_2OVER"] = 112] = "OP_2OVER";
  Opcode[Opcode["OP_2ROT"] = 113] = "OP_2ROT";
  Opcode[Opcode["OP_2SWAP"] = 114] = "OP_2SWAP";
  Opcode[Opcode["OP_IFDUP"] = 115] = "OP_IFDUP";
  Opcode[Opcode["OP_DEPTH"] = 116] = "OP_DEPTH";
  Opcode[Opcode["OP_DROP"] = 117] = "OP_DROP";
  Opcode[Opcode["OP_DUP"] = 118] = "OP_DUP";
  Opcode[Opcode["OP_NIP"] = 119] = "OP_NIP";
  Opcode[Opcode["OP_OVER"] = 120] = "OP_OVER";
  Opcode[Opcode["OP_PICK"] = 121] = "OP_PICK";
  Opcode[Opcode["OP_ROLL"] = 122] = "OP_ROLL";
  Opcode[Opcode["OP_ROT"] = 123] = "OP_ROT";
  Opcode[Opcode["OP_SWAP"] = 124] = "OP_SWAP";
  Opcode[Opcode["OP_TUCK"] = 125] = "OP_TUCK";
  Opcode[Opcode["OP_CAT"] = 126] = "OP_CAT";
  Opcode[Opcode["OP_SPLIT"] = 127] = "OP_SPLIT";
  Opcode[Opcode["OP_NUM2BIN"] = 128] = "OP_NUM2BIN";
  Opcode[Opcode["OP_BIN2NUM"] = 129] = "OP_BIN2NUM";
  Opcode[Opcode["OP_SIZE"] = 130] = "OP_SIZE";
  Opcode[Opcode["OP_INVERT"] = 131] = "OP_INVERT";
  Opcode[Opcode["OP_AND"] = 132] = "OP_AND";
  Opcode[Opcode["OP_OR"] = 133] = "OP_OR";
  Opcode[Opcode["OP_XOR"] = 134] = "OP_XOR";
  Opcode[Opcode["OP_EQUAL"] = 135] = "OP_EQUAL";
  Opcode[Opcode["OP_EQUALVERIFY"] = 136] = "OP_EQUALVERIFY";
  Opcode[Opcode["OP_RESERVED1"] = 137] = "OP_RESERVED1";
  Opcode[Opcode["OP_RESERVED2"] = 138] = "OP_RESERVED2";
  Opcode[Opcode["OP_1ADD"] = 139] = "OP_1ADD";
  Opcode[Opcode["OP_1SUB"] = 140] = "OP_1SUB";
  Opcode[Opcode["OP_2MUL"] = 141] = "OP_2MUL";
  Opcode[Opcode["OP_2DIV"] = 142] = "OP_2DIV";
  Opcode[Opcode["OP_NEGATE"] = 143] = "OP_NEGATE";
  Opcode[Opcode["OP_ABS"] = 144] = "OP_ABS";
  Opcode[Opcode["OP_NOT"] = 145] = "OP_NOT";
  Opcode[Opcode["OP_0NOTEQUAL"] = 146] = "OP_0NOTEQUAL";
  Opcode[Opcode["OP_ADD"] = 147] = "OP_ADD";
  Opcode[Opcode["OP_SUB"] = 148] = "OP_SUB";
  Opcode[Opcode["OP_MUL"] = 149] = "OP_MUL";
  Opcode[Opcode["OP_DIV"] = 150] = "OP_DIV";
  Opcode[Opcode["OP_MOD"] = 151] = "OP_MOD";
  Opcode[Opcode["OP_LSHIFT"] = 152] = "OP_LSHIFT";
  Opcode[Opcode["OP_RSHIFT"] = 153] = "OP_RSHIFT";
  Opcode[Opcode["OP_BOOLAND"] = 154] = "OP_BOOLAND";
  Opcode[Opcode["OP_BOOLOR"] = 155] = "OP_BOOLOR";
  Opcode[Opcode["OP_NUMEQUAL"] = 156] = "OP_NUMEQUAL";
  Opcode[Opcode["OP_NUMEQUALVERIFY"] = 157] = "OP_NUMEQUALVERIFY";
  Opcode[Opcode["OP_NUMNOTEQUAL"] = 158] = "OP_NUMNOTEQUAL";
  Opcode[Opcode["OP_LESSTHAN"] = 159] = "OP_LESSTHAN";
  Opcode[Opcode["OP_GREATERTHAN"] = 160] = "OP_GREATERTHAN";
  Opcode[Opcode["OP_LESSTHANOREQUAL"] = 161] = "OP_LESSTHANOREQUAL";
  Opcode[Opcode["OP_GREATERTHANOREQUAL"] = 162] = "OP_GREATERTHANOREQUAL";
  Opcode[Opcode["OP_MIN"] = 163] = "OP_MIN";
  Opcode[Opcode["OP_MAX"] = 164] = "OP_MAX";
  Opcode[Opcode["OP_WITHIN"] = 165] = "OP_WITHIN";
  Opcode[Opcode["OP_RIPEMD160"] = 166] = "OP_RIPEMD160";
  Opcode[Opcode["OP_SHA1"] = 167] = "OP_SHA1";
  Opcode[Opcode["OP_SHA256"] = 168] = "OP_SHA256";
  Opcode[Opcode["OP_HASH160"] = 169] = "OP_HASH160";
  Opcode[Opcode["OP_HASH256"] = 170] = "OP_HASH256";
  Opcode[Opcode["OP_CODESEPARATOR"] = 171] = "OP_CODESEPARATOR";
  Opcode[Opcode["OP_CHECKSIG"] = 172] = "OP_CHECKSIG";
  Opcode[Opcode["OP_CHECKSIGVERIFY"] = 173] = "OP_CHECKSIGVERIFY";
  Opcode[Opcode["OP_CHECKMULTISIG"] = 174] = "OP_CHECKMULTISIG";
  Opcode[Opcode["OP_CHECKMULTISIGVERIFY"] = 175] = "OP_CHECKMULTISIGVERIFY";
  Opcode[Opcode["OP_NOP2"] = 177] = "OP_NOP2";
  Opcode[Opcode["OP_CHECKLOCKTIMEVERIFY"] = 177] = "OP_CHECKLOCKTIMEVERIFY";
  Opcode[Opcode["OP_NOP3"] = 178] = "OP_NOP3";
  Opcode[Opcode["OP_CHECKSEQUENCEVERIFY"] = 178] = "OP_CHECKSEQUENCEVERIFY";
  Opcode[Opcode["OP_NOP1"] = 176] = "OP_NOP1";
  Opcode[Opcode["OP_NOP4"] = 179] = "OP_NOP4";
  Opcode[Opcode["OP_NOP5"] = 180] = "OP_NOP5";
  Opcode[Opcode["OP_NOP6"] = 181] = "OP_NOP6";
  Opcode[Opcode["OP_NOP7"] = 182] = "OP_NOP7";
  Opcode[Opcode["OP_NOP8"] = 183] = "OP_NOP8";
  Opcode[Opcode["OP_NOP9"] = 184] = "OP_NOP9";
  Opcode[Opcode["OP_NOP10"] = 185] = "OP_NOP10";
  Opcode[Opcode["OP_CHECKDATASIG"] = 186] = "OP_CHECKDATASIG";
  Opcode[Opcode["OP_CHECKDATASIGVERIFY"] = 187] = "OP_CHECKDATASIGVERIFY";
  Opcode[Opcode["OP_REVERSEBYTES"] = 188] = "OP_REVERSEBYTES";
  Opcode[Opcode["OP_INPUTINDEX"] = 192] = "OP_INPUTINDEX";
  Opcode[Opcode["OP_ACTIVEBYTECODE"] = 193] = "OP_ACTIVEBYTECODE";
  Opcode[Opcode["OP_TXVERSION"] = 194] = "OP_TXVERSION";
  Opcode[Opcode["OP_TXINPUTCOUNT"] = 195] = "OP_TXINPUTCOUNT";
  Opcode[Opcode["OP_TXOUTPUTCOUNT"] = 196] = "OP_TXOUTPUTCOUNT";
  Opcode[Opcode["OP_TXLOCKTIME"] = 197] = "OP_TXLOCKTIME";
  Opcode[Opcode["OP_UTXOVALUE"] = 198] = "OP_UTXOVALUE";
  Opcode[Opcode["OP_UTXOBYTECODE"] = 199] = "OP_UTXOBYTECODE";
  Opcode[Opcode["OP_OUTPOINTHASH"] = 200] = "OP_OUTPOINTHASH";
  Opcode[Opcode["OP_INPUTBYTECODE"] = 202] = "OP_INPUTBYTECODE";
  Opcode[Opcode["OP_INPUTSEQUENCENUMBER"] = 203] = "OP_INPUTSEQUENCENUMBER";
  Opcode[Opcode["OP_OUTPUTVALUE"] = 204] = "OP_OUTPUTVALUE";
  Opcode[Opcode["OP_OUTPUTBYTECODE"] = 205] = "OP_OUTPUTBYTECODE";
  Opcode[Opcode["OP_INPUTTYPE"] = 206] = "OP_INPUTTYPE";
  Opcode[Opcode["OP_OUTPUTTYPE"] = 207] = "OP_OUTPUTTYPE";
  Opcode[Opcode["OP_INPUTVALUE"] = 208] = "OP_INPUTVALUE";
  Opcode[Opcode["OP_PARSE"] = 230] = "OP_PARSE";
  Opcode[Opcode["OP_STORE"] = 231] = "OP_STORE";
  Opcode[Opcode["OP_LOAD"] = 232] = "OP_LOAD";
  Opcode[Opcode["OP_PLACE"] = 233] = "OP_PLACE";
  Opcode[Opcode["OP_PUSH_TX_STATE"] = 234] = "OP_PUSH_TX_STATE";
  Opcode[Opcode["OP_SETBMD"] = 235] = "OP_SETBMD";
  Opcode[Opcode["OP_BIN2BIGNUM"] = 236] = "OP_BIN2BIGNUM";
  Opcode[Opcode["OP_EXEC"] = 237] = "OP_EXEC";
  Opcode[Opcode["OP_MERKLEROOT"] = 238] = "OP_MERKLEROOT";
  Opcode[Opcode["FIRST_UNDEFINED_OP_VALUE"] = 239] = "FIRST_UNDEFINED_OP_VALUE";
  Opcode[Opcode["OP_INVALIDOPCODE"] = 255] = "OP_INVALIDOPCODE";
  return Opcode;
})({});
class $92c0719d4ab9ac45$export$2e2bcd8739ae039 {
  constructor(val) {
    if (isNumber$1(val)) this.num = val;
    else if (isString(val)) this.num = $92c0719d4ab9ac45$export$393941f88fd16991[val];
    else throw new TypeError('Unrecognized val type: "' + typeof val + '" for Opcode');
  }
  static fromBuffer(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf must be Buffer");
    return new $92c0719d4ab9ac45$export$2e2bcd8739ae039(Number("0x" + buf.toString("hex")));
  }
  static fromNumber(num) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isNumber$1(num), "num must be number");
    return new $92c0719d4ab9ac45$export$2e2bcd8739ae039(num);
  }
  static fromString(str) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(str), "str must be string");
    let value = $92c0719d4ab9ac45$export$393941f88fd16991[str];
    if (typeof value === "undefined") throw new TypeError("Invalid opcodestr");
    return new $92c0719d4ab9ac45$export$2e2bcd8739ae039(value);
  }
  static smallInt(n) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isNumber$1(n), "n should be number");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(n >= 0 && n <= 16, "n must be between 0 and 16");
    if (n === 0) return new $92c0719d4ab9ac45$export$2e2bcd8739ae039("OP_0");
    return new $92c0719d4ab9ac45$export$2e2bcd8739ae039(81 + n - 1);
  }
  /**
  * @returns true if opcode is one of OP_0, OP_1, ..., OP_16
  */
  static isSmallIntOp(opcode) {
    if (opcode instanceof $92c0719d4ab9ac45$export$2e2bcd8739ae039) opcode = opcode.toNumber();
    return opcode === 0 || opcode >= 81 && opcode <= 96;
  }
  toHex() {
    return this.num.toString(16);
  }
  toBuffer() {
    return Buffer$1.from(this.toHex(), "hex");
  }
  toNumber() {
    return this.num;
  }
  toString() {
    let str = $92c0719d4ab9ac45$export$393941f88fd16991[this.num];
    if (typeof str === "undefined") throw new Error("Opcode does not have a string representation");
    return str;
  }
  /**
  * Will return a string formatted for the console
  *
  * @returns Script opcode
  */
  inspect() {
    return "<Opcode: " + this.toString() + ", hex: " + this.toHex() + ", decimal: " + this.num + ">";
  }
  /**
  * Comes from nexad's script DecodeOP_N function
  * @param opcode
  * @returns numeric value in range of 0 to 16
  */
  static decodeOP_N(opcode) {
    if (opcode === 0) return 0;
    else if (opcode >= 81 && opcode <= 96) return opcode - 80;
    else throw new Error("Invalid opcode: " + JSON.stringify(opcode));
  }
}
class $90f45db77a786f2b$export$2e2bcd8739ae039 {
  constructor(from) {
    this.append = this.add;
    this.chunks = [];
    if (!from) return;
    if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(from)) return $90f45db77a786f2b$export$2e2bcd8739ae039.fromBuffer(from);
    else if (from instanceof $90f45db77a786f2b$export$2e2bcd8739ae039) return $90f45db77a786f2b$export$2e2bcd8739ae039.fromBuffer(from.toBuffer());
    else if (isString(from)) return $90f45db77a786f2b$export$2e2bcd8739ae039.fromString(from);
    else if ($90f45db77a786f2b$export$2e2bcd8739ae039._isScriptObject(from)) this.set(from);
  }
  static _isScriptObject(obj) {
    return isObject$1(obj) && "chunks" in obj && isArray(obj.chunks);
  }
  static _isScriptChunk(obj) {
    return isObject$1(obj) && "opcodenum" in obj;
  }
  set(obj) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($90f45db77a786f2b$export$2e2bcd8739ae039._isScriptObject(obj), "obj");
    this.chunks = obj.chunks;
    return this;
  }
  /**
  * @returns a new empty script
  */
  static empty() {
    return new $90f45db77a786f2b$export$2e2bcd8739ae039();
  }
  static fromBuffer(buffer) {
    let script = new $90f45db77a786f2b$export$2e2bcd8739ae039();
    script.chunks = [];
    let br = new $12fea2c2eb591556$export$2e2bcd8739ae039(buffer);
    while (!br.finished()) try {
      let opcodenum = br.readUInt8();
      let len, buf;
      if (opcodenum > 0 && opcodenum < (0, $92c0719d4ab9ac45$export$393941f88fd16991).OP_PUSHDATA1) {
        len = opcodenum;
        script.chunks.push({
          buf: br.read(len),
          len,
          opcodenum
        });
      } else if (opcodenum === (0, $92c0719d4ab9ac45$export$393941f88fd16991).OP_PUSHDATA1) {
        len = br.readUInt8();
        buf = br.read(len);
        script.chunks.push({
          buf,
          len,
          opcodenum
        });
      } else if (opcodenum === (0, $92c0719d4ab9ac45$export$393941f88fd16991).OP_PUSHDATA2) {
        len = br.readUInt16LE();
        buf = br.read(len);
        script.chunks.push({
          buf,
          len,
          opcodenum
        });
      } else if (opcodenum === (0, $92c0719d4ab9ac45$export$393941f88fd16991).OP_PUSHDATA4) {
        len = br.readUInt32LE();
        buf = br.read(len);
        script.chunks.push({
          buf,
          len,
          opcodenum
        });
      } else script.chunks.push({
        opcodenum
      });
    } catch (e) {
      throw e instanceof RangeError ? new Error(`Invalid script buffer: can't parse valid script from given buffer ${buffer.toString("hex")}`) : e;
    }
    return script;
  }
  toBuffer() {
    let bw = new $35852622c8c617e8$export$2e2bcd8739ae039();
    this.chunks.forEach((chunk) => {
      bw.writeUInt8(chunk.opcodenum);
      if (chunk.buf) {
        if (chunk.opcodenum < $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1) bw.write(chunk.buf);
        else if (chunk.opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1) {
          bw.writeUInt8(chunk.len);
          bw.write(chunk.buf);
        } else if (chunk.opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA2) {
          bw.writeUInt16LE(chunk.len);
          bw.write(chunk.buf);
        } else if (chunk.opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA4) {
          bw.writeUInt32LE(chunk.len);
          bw.write(chunk.buf);
        }
      }
    });
    return bw.concat();
  }
  static fromHex(str) {
    return new $90f45db77a786f2b$export$2e2bcd8739ae039(Buffer$1.from(str, "hex"));
  }
  static fromString(str) {
    if ($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(str) || str.length === 0) return this.fromHex(str);
    let script = new $90f45db77a786f2b$export$2e2bcd8739ae039();
    script.chunks = [];
    let tokens = str.split(" ");
    let i = 0;
    while (i < tokens.length) {
      let token = tokens[i];
      let opcode = new $92c0719d4ab9ac45$export$2e2bcd8739ae039(token);
      let opcodenum = opcode.toNumber();
      if (isUndefined(opcodenum)) {
        opcodenum = parseInt(token);
        if (opcodenum > 0 && opcodenum < $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1) {
          script.chunks.push({
            buf: Buffer$1.from(tokens[i + 1].slice(2), "hex"),
            len: opcodenum,
            opcodenum
          });
          i = i + 2;
        } else throw new Error("Invalid script: " + JSON.stringify(str));
      } else if (opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1 || opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA2 || opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA4) {
        if (tokens[i + 2].slice(0, 2) !== "0x") throw new Error("Pushdata data must start with 0x");
        script.chunks.push({
          buf: Buffer$1.from(tokens[i + 2].slice(2), "hex"),
          len: parseInt(tokens[i + 1]),
          opcodenum
        });
        i = i + 3;
      } else {
        script.chunks.push({
          opcodenum
        });
        i = i + 1;
      }
    }
    return script;
  }
  static fromASM(str) {
    let script = new $90f45db77a786f2b$export$2e2bcd8739ae039();
    script.chunks = [];
    let tokens = str.split(" ");
    let i = 0;
    while (i < tokens.length) {
      let token = tokens[i];
      let opcode = new $92c0719d4ab9ac45$export$2e2bcd8739ae039(token);
      let opcodenum = opcode.toNumber();
      if (isUndefined(opcodenum)) {
        let buf = Buffer$1.from(tokens[i], "hex");
        let len = buf.length;
        if (len >= 0 && len < $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1) opcodenum = len;
        else if (len < Math.pow(2, 8)) opcodenum = $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1;
        else if (len < Math.pow(2, 16)) opcodenum = $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA2;
        else if (len < Math.pow(2, 32)) opcodenum = $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA4;
        script.chunks.push({
          buf,
          len: buf.length,
          opcodenum
        });
        i = i + 1;
      } else {
        script.chunks.push({
          opcodenum
        });
        i = i + 1;
      }
    }
    return script;
  }
  static _chunkToString(chunk, toASM = false) {
    let opcodenum = chunk.opcodenum;
    let str = "";
    if (!chunk.buf) {
      if (typeof $92c0719d4ab9ac45$export$393941f88fd16991[opcodenum] !== "undefined") {
        if (toASM) {
          if (opcodenum === 0)
            str = str + " 0";
          else if (opcodenum === 79)
            str = str + " -1";
          else str = str + " " + new $92c0719d4ab9ac45$export$2e2bcd8739ae039(opcodenum).toString();
        } else str = str + " " + new $92c0719d4ab9ac45$export$2e2bcd8739ae039(opcodenum).toString();
      } else {
        let numstr = opcodenum.toString(16);
        if (numstr.length % 2 !== 0) numstr = "0" + numstr;
        if (toASM) str = str + " " + numstr;
        else str = str + " 0x" + numstr;
      }
    } else {
      if (!toASM && (opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1 || opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA2 || opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA4)) str = str + " " + new $92c0719d4ab9ac45$export$2e2bcd8739ae039(opcodenum).toString();
      if (chunk.len > 0) {
        if (toASM) str = str + " " + chunk.buf.toString("hex");
        else str = str + " " + chunk.len + " 0x" + chunk.buf.toString("hex");
      }
    }
    return str;
  }
  toASM() {
    return this.chunks.map((chunk) => $90f45db77a786f2b$export$2e2bcd8739ae039._chunkToString(chunk, true)).join("").substring(1);
  }
  toString() {
    return this.chunks.map((chunk) => $90f45db77a786f2b$export$2e2bcd8739ae039._chunkToString(chunk)).join("").substring(1);
  }
  toHex() {
    return this.toBuffer().toString("hex");
  }
  inspect() {
    return `<Script: ${this}>`;
  }
  /**
  * Adds a script element to the end of the script.
  *
  * @param param a script element to add
  * @returns this script instance
  *
  */
  add(param) {
    this._addByType(param, false);
    return this;
  }
  /**
  * Adds a script element at the start of the script.
  * @param param a script element to add
  * @returns this script instance
  */
  prepend(param) {
    this._addByType(param, true);
    return this;
  }
  _addByType(obj, prepend) {
    if (typeof obj === "string") this._addOpcode(obj, prepend);
    else if (typeof obj === "number") this._addOpcode(obj, prepend);
    else if (obj instanceof $92c0719d4ab9ac45$export$2e2bcd8739ae039) this._addOpcode(obj, prepend);
    else if (typeof obj === "bigint") {
      if (obj <= 16n) this._addOpcode($92c0719d4ab9ac45$export$2e2bcd8739ae039.smallInt(Number(obj)), prepend);
      else if (obj === 0x81n) this._addOpcode($92c0719d4ab9ac45$export$393941f88fd16991.OP_1NEGATE, prepend);
      else this._addBuffer(new $5aa97aebe18a7924$export$2e2bcd8739ae039(obj.toString()).toScriptNumBuffer(), prepend);
    } else if (typeof obj === "boolean") this._addOpcode(obj ? $92c0719d4ab9ac45$export$393941f88fd16991.OP_TRUE : $92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE, prepend);
    else if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(obj)) this._addBuffer(obj, prepend);
    else if (obj instanceof $90f45db77a786f2b$export$2e2bcd8739ae039) this.chunks = this.chunks.concat(obj.chunks);
    else if ($90f45db77a786f2b$export$2e2bcd8739ae039._isScriptChunk(obj)) this._insertAtPosition(obj, prepend);
    else throw new Error("Invalid script chunk");
  }
  _insertAtPosition(chunk, prepend) {
    if (prepend) this.chunks.unshift(chunk);
    else this.chunks.push(chunk);
  }
  _addOpcode(opcode, prepend) {
    let op;
    if (typeof opcode === "number") op = opcode;
    else if (opcode instanceof $92c0719d4ab9ac45$export$2e2bcd8739ae039) op = opcode.toNumber();
    else op = new $92c0719d4ab9ac45$export$2e2bcd8739ae039(opcode).toNumber();
    this._insertAtPosition({
      opcodenum: op
    }, prepend);
    return this;
  }
  _addBuffer(buf, prepend) {
    let opcodenum;
    let len = buf.length;
    if (len >= 0 && len < $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1) opcodenum = len;
    else if (len < Math.pow(2, 8)) opcodenum = $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1;
    else if (len < Math.pow(2, 16)) opcodenum = $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA2;
    else if (len < Math.pow(2, 32)) opcodenum = $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA4;
    else throw new Error("You can't push that much data");
    this._insertAtPosition({
      buf,
      len,
      opcodenum
    }, prepend);
    return this;
  }
  /**
  * Compares a script with another script
  */
  equals(script) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(script instanceof $90f45db77a786f2b$export$2e2bcd8739ae039, "Must provide another script");
    if (this.chunks.length !== script.chunks.length) return false;
    for (let i = 0; i < this.chunks.length; i++) {
      if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(this.chunks[i].buf) && !$9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(script.chunks[i].buf)) return false;
      if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(this.chunks[i].buf) && !this.chunks[i].buf.equals(script.chunks[i].buf)) return false;
      else if (this.chunks[i].opcodenum !== script.chunks[i].opcodenum) return false;
    }
    return true;
  }
  /**
  * Analogous to nexad's FindAndDelete. Find and delete equivalent chunks,
  * typically used with push data chunks. Note that this will find and delete
  * not just the same data, but the same data with the same push data op as
  * produced by default. i.e., if a pushdata in a tx does not use the minimal
  * pushdata op, then when you try to remove the data it is pushing, it will not
  * be removed, because they do not use the same pushdata op.
  */
  findAndDelete(script) {
    let buf = script.toBuffer();
    let hex = buf.toString("hex");
    for (let i = 0; i < this.chunks.length; i++) {
      let script2 = new $90f45db77a786f2b$export$2e2bcd8739ae039({
        chunks: [
          this.chunks[i]
        ]
      });
      let buf2 = script2.toBuffer();
      let hex2 = buf2.toString("hex");
      if (hex === hex2) this.chunks.splice(i, 1);
    }
    return this;
  }
  /**
  * Comes from nexad's script interpreter CheckMinimalPush function
  * @returns true if the chunk {i} is the smallest way to push that particular data.
  */
  checkMinimalPush(i) {
    let chunk = this.chunks[i];
    let buf = chunk.buf;
    let opcodenum = chunk.opcodenum;
    if (!buf) return true;
    if (buf.length === 0)
      return opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_0;
    else if (buf.length === 1 && buf[0] >= 1 && buf[0] <= 16)
      return false;
    else if (buf.length === 1 && buf[0] === 129)
      return false;
    else if (buf.length <= 75)
      return opcodenum === buf.length;
    else if (buf.length <= 255)
      return opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1;
    else if (buf.length <= 65535)
      return opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA2;
    return true;
  }
  /**
  * Comes from bitcoind's script GetSigOpCount(boolean) function
  * @param accurate default true
  * @returns number of signature operations required by this script
  */
  getSignatureOperationsCount(accurate = true) {
    let n = 0;
    let lastOpcode = $92c0719d4ab9ac45$export$393941f88fd16991.OP_INVALIDOPCODE;
    this.chunks.forEach((chunk) => {
      let opcode = chunk.opcodenum;
      if (opcode == $92c0719d4ab9ac45$export$393941f88fd16991.OP_CHECKSIG || opcode == $92c0719d4ab9ac45$export$393941f88fd16991.OP_CHECKSIGVERIFY) n++;
      else if (opcode == $92c0719d4ab9ac45$export$393941f88fd16991.OP_CHECKMULTISIG || opcode == $92c0719d4ab9ac45$export$393941f88fd16991.OP_CHECKMULTISIGVERIFY) {
        if (accurate && lastOpcode >= $92c0719d4ab9ac45$export$393941f88fd16991.OP_1 && lastOpcode <= $92c0719d4ab9ac45$export$393941f88fd16991.OP_16) n += $92c0719d4ab9ac45$export$2e2bcd8739ae039.decodeOP_N(lastOpcode);
        else n += 20;
      }
      lastOpcode = opcode;
    });
    return n;
  }
  /**
  * @returns true if the script is only composed of data pushing
  * opcodes or small int opcodes (OP_0, OP_1, ..., OP_16)
  */
  isPushOnly() {
    return this.chunks.every((chunk) => chunk.opcodenum <= $92c0719d4ab9ac45$export$393941f88fd16991.OP_16 || chunk.opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA1 || chunk.opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA2 || chunk.opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_PUSHDATA4);
  }
  /**
  * @returns true if this is a pay to script template output script
  * @remarks for well-known-1 template use {@link isPublicKeyTemplateOut}
  */
  isScriptTemplateOut() {
    if (this.chunks.length < 3) return false;
    let hasGroup = this.chunks[0].opcodenum !== $92c0719d4ab9ac45$export$393941f88fd16991.OP_0;
    let minLength = hasGroup ? 4 : 3;
    let templateIndex = hasGroup ? 2 : 1;
    let constraintIndex = hasGroup ? 3 : 2;
    let isTemplate = this.chunks.length >= minLength && $9f918c10ad4fef51$export$2e2bcd8739ae039.isHashBuffer(this.chunks[templateIndex].buf) && ($9f918c10ad4fef51$export$2e2bcd8739ae039.isHashBuffer(this.chunks[constraintIndex].buf) || this.chunks[constraintIndex].opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE);
    if (hasGroup) isTemplate &&= !!(this.chunks[0].buf && this.chunks[0].buf.length >= 32 && // group id
    this.chunks[1].buf && this.chunks[1].buf.length >= 2 && this.chunks[1].buf.length <= 8);
    if (isTemplate && this.chunks.length > minLength) {
      let visibleArgs = new $90f45db77a786f2b$export$2e2bcd8739ae039({
        chunks: this.chunks.slice(minLength)
      });
      isTemplate = visibleArgs.isPushOnly();
    }
    return isTemplate;
  }
  /**
  * Checks if this script is a valid pay to script template input script
  * 
  * @returns true if this is a pay to script template form input script
  * @remarks for well-known-1 template use {@link isPublicKeyTemplateIn}
  */
  isScriptTemplateIn() {
    return this.chunks.length > 1 && $9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(this.chunks[0].buf) && this.isPushOnly();
  }
  /**
  * @returns true if this is a pay to pubkey template output script (well-known-1, p2pkt)
  */
  isPublicKeyTemplateOut() {
    if (this.chunks.length < 3) return false;
    let hasGroup = this.chunks[0].opcodenum !== $92c0719d4ab9ac45$export$393941f88fd16991.OP_0;
    let minLength = hasGroup ? 4 : 3;
    let templateIndex = hasGroup ? 2 : 1;
    let constraintIndex = hasGroup ? 3 : 2;
    let isTemplate = this.chunks.length === minLength && this.chunks[templateIndex].opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_1 && $9f918c10ad4fef51$export$2e2bcd8739ae039.isHashBuffer(this.chunks[constraintIndex].buf);
    if (hasGroup) isTemplate &&= !!(this.chunks[0].buf && this.chunks[0].buf.length >= 32 && // group id
    this.chunks[1].buf && this.chunks[1].buf.length >= 2 && this.chunks[1].buf.length <= 8);
    return isTemplate;
  }
  /**
  * @returns true if this is a pay to public key template input script
  */
  isPublicKeyTemplateIn() {
    if (this.chunks.length != 2) return false;
    let pubkeyPushBuf = this.chunks[0].buf;
    let signatureBuf = this.chunks[1].buf;
    if (signatureBuf && signatureBuf.length >= 64 && signatureBuf.length <= 68 && pubkeyPushBuf?.length === 34) {
      let pubkeyBuf = $90f45db77a786f2b$export$2e2bcd8739ae039.fromBuffer(pubkeyPushBuf).chunks[0].buf;
      return pubkeyBuf?.length === 33 && (pubkeyBuf[0] === 3 || pubkeyBuf[0] === 2);
    }
    return false;
  }
  /**
  * @returns true if this is a pay to pubkey hash output script
  */
  isPublicKeyHashOut() {
    return !!(this.chunks.length === 5 && this.chunks[0].opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_DUP && this.chunks[1].opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_HASH160 && this.chunks[2].buf && this.chunks[2].buf.length === 20 && this.chunks[3].opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_EQUALVERIFY && this.chunks[4].opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_CHECKSIG);
  }
  /**
  * @returns {boolean} if this is a pay to public key hash input script
  */
  isPublicKeyHashIn() {
    if (this.chunks.length != 2) return false;
    let signatureBuf = this.chunks[0].buf;
    let pubkeyBuf = this.chunks[1].buf;
    if (signatureBuf && signatureBuf.length && pubkeyBuf && pubkeyBuf.length) {
      let version = pubkeyBuf[0];
      if ((version === 4 || version === 6 || version === 7) && pubkeyBuf.length === 65) return true;
      else if ((version === 3 || version === 2) && pubkeyBuf.length === 33) return true;
    }
    return false;
  }
  /**
  * @returns true if this is a valid standard OP_RETURN output
  */
  isDataOut() {
    let step1 = this.chunks.length >= 1 && this.chunks[0].opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_RETURN && this.toBuffer().length <= 223;
    if (!step1) return false;
    let chunks = this.chunks.slice(1);
    let script2 = new $90f45db77a786f2b$export$2e2bcd8739ae039({
      chunks
    });
    return script2.isPushOnly();
  }
  /**
  * @returns true if this is a valid Token Description OP_RETURN output
  */
  isTokenDescriptionOut() {
    let step1 = inRange(this.chunks.length, 2, 8) && this.chunks[0].opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_RETURN && this.chunks[1].len === 4;
    return step1 && new $90f45db77a786f2b$export$2e2bcd8739ae039({
      chunks: this.chunks.slice(1)
    }).isPushOnly();
  }
  /**
  * Will retrieve the Public Key buffer from p2pkt/p2pkh input scriptSig
  */
  getPublicKey() {
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.isPublicKeyHashIn() || this.isPublicKeyTemplateIn(), "Can't retrieve PublicKey from a non-PKT or non-PKH input");
    return this.isPublicKeyHashIn() ? this.chunks[1].buf : $90f45db77a786f2b$export$2e2bcd8739ae039.fromBuffer(this.chunks[0].buf).chunks[0].buf;
  }
  /**
  * Will retrieve the Public Key Hash buffer from p2pkh output scriptPubKey
  */
  getPublicKeyHash() {
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.isPublicKeyHashOut(), "Can't retrieve PublicKeyHash from a non-PKH output");
    return this.chunks[2].buf;
  }
  /**
  * Will retrieve the Template Hash from p2pkt/p2st output scriptPubKey
  * 
  * @returns OP_1 if its p2pkt, otherwise the template hash buffer
  */
  getTemplateHash() {
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.isPublicKeyTemplateOut() || this.isScriptTemplateOut(), "Can't retrieve TemplateHash from a non-PST output");
    if (this.isPublicKeyTemplateOut()) return $92c0719d4ab9ac45$export$393941f88fd16991.OP_1;
    let hasGroup = this.chunks[0].opcodenum !== $92c0719d4ab9ac45$export$393941f88fd16991.OP_0;
    return hasGroup ? this.chunks[2].buf : this.chunks[1].buf;
  }
  /**
  * Will retrieve the Constraint Hash from p2pkt/p2st output scriptPubKey
  * 
  * @returns The constraint hash buffer, or OP_FALSE if not included
  */
  getConstraintHash() {
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.isPublicKeyTemplateOut() || this.isScriptTemplateOut(), "Can't retrieve ConstraintHash from a non-PST output");
    let hasGroup = this.chunks[0].opcodenum !== $92c0719d4ab9ac45$export$393941f88fd16991.OP_0;
    let constraintIndex = hasGroup ? 3 : 2;
    if (this.isPublicKeyTemplateOut()) return this.chunks[constraintIndex].buf;
    return this.chunks[constraintIndex].opcodenum === $92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE ? $92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE : this.chunks[constraintIndex].buf;
  }
  /**
  * Will retrieve the Group Identifier number from Token Description OP_RETURN output
  * 
  * @remarks This method doesn't check if the group id number is fit to NRC1/NRC2 etc. 
  */
  getGroupIdType() {
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.isTokenDescriptionOut(), "Can't retrieve GroupIdType from a non Token Description output");
    return $5aa97aebe18a7924$export$2e2bcd8739ae039.fromScriptNumBuffer(this.chunks[1].buf).toNumber();
  }
}
class $92cd415860c918d9$export$2e2bcd8739ae039 {
  /* c8 ignore start */
  /** @deprecated use data */
  get hashBuffer() {
    return this.data;
  }
  /* c8 ignore stop */
  /**
  * Instantiate an address from an address String or Buffer, a public key or script hash Buffer,
  * or an instance of {@link PublicKey} or {@link Script}.
  *
  * This is an immutable class, and if the first parameter provided to this constructor is an
  * `Address` instance, the same argument will be returned.
  *
  * An address has two key properties: `network` and `type`. The type is either
  * `AddressType.PayToPublicKeyHash` (value is the `'P2PKH'` string)
  * or `AddressType.PayToScriptTemplate` (the string `'P2ST'`). The network is an instance of {@link Network} or network name.
  * You can quickly check whether an address is of a given kind by using the methods
  * `isPayToPublicKeyHash` and `isPayToScriptTemplate`
  *
  * @example
  * ```javascript
  * // validate that an input field is valid
  * let error = Address.getValidationError(input, 'testnet');
  * if (!error) {
  *   let address = new Address(input, 'testnet');
  * } else {
  *   // invalid network or checksum (typo?)
  *   let message = error.messsage;
  * }
  *
  * // get an address from a public key
  * let address = Address.fromPublicKey(publicKey, 'testnet').toString();
  * ```
  *
  * @param data The encoded data in various formats
  * @param network The network: 'mainnet' (default) or 'testnet'
  * @param type The type of address: 'P2ST' (default) or 'P2PKH' or 'GROUP'
  * @returns A new valid and frozen instance of an Address
  */
  constructor(data, network, type) {
    this.toNexaAddress = this.toString;
    this.toObject = this.toJSON;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isNil(data), "First argument is required, please include address data.");
    if (data instanceof $92cd415860c918d9$export$2e2bcd8739ae039) return data;
    if (isString(data)) return $92cd415860c918d9$export$2e2bcd8739ae039.fromString(data);
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(data), "data must be Address, string or Buffer");
    $92cd415860c918d9$export$2e2bcd8739ae039.validateParams(network, type);
    this.data = data;
    this.network = $a89918d61ea4dca0$export$f09b1917886389c3.get(network) || $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork;
    this.type = type || $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToScriptTemplate;
  }
  static validateParams(network, type) {
    if (network && !$a89918d61ea4dca0$export$f09b1917886389c3.get(network)) throw new TypeError('Second argument must be "mainnet" or "testnet".');
    if (type && type !== $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToScriptTemplate && type !== $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.GroupIdAddress && type !== $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash) throw new TypeError('Third argument must be "P2ST", "P2PKH" or "GROUP"');
  }
  /**
  * @param address string
  * 
  * @returns A new valid and frozen instance of an Address
  */
  static fromString(address) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(address), "parameter supplied is not a string.");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(address.length > 34, "Invalid Address string provided");
    let parts = $c889a5b1bdeeb100$export$2e2bcd8739ae039.decode(address);
    let network = $a89918d61ea4dca0$export$f09b1917886389c3.get(parts.prefix, "prefix");
    return new $92cd415860c918d9$export$2e2bcd8739ae039(parts.data, network, parts.type);
  }
  static {
    this.decodeNexaAddress = this.fromString;
  }
  /**
  * Will return a cashaddr representation of the address. Always return lower case
  * Can be converted by the caller to uppercase is needed (still valid).
  *
  * @returns Nexa address
  */
  toString() {
    return $c889a5b1bdeeb100$export$2e2bcd8739ae039.encode(this.network.prefix, this.type, this.data);
  }
  /**
  * Will return a string formatted for the console
  *
  * @returns {string} Bitcoin address
  */
  inspect() {
    return `<Address: ${this}, type: ${this.type}, network: ${this.network}>`;
  }
  /**
  * Instantiate an address from an Object
  *
  * @param obj - A JSON object with keys: data, network and type
  * @returns A new valid instance of an Address
  */
  static fromObject(obj) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(obj?.data), "Must provide a `data` property");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(obj?.type), "Must provide a `type` property");
    $e44f707fde477092$export$2e2bcd8739ae039.validateState($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(obj.data), `Unexpected data property, expected to be hex.`);
    let hashBuffer = Buffer$1.from(obj.data, "hex");
    return new $92cd415860c918d9$export$2e2bcd8739ae039(hashBuffer, obj.network, obj.type);
  }
  /**
  * @returns A plain object with the address information
  */
  toJSON() {
    return {
      data: this.data.toString("hex"),
      type: this.type,
      network: this.network.toString()
    };
  }
  /**
  * @return true if an address is of pay to public key hash type
  */
  isPayToPublicKeyHash() {
    return this.type === $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash;
  }
  /**
  * @return true if an address is of pay to script template type
  */
  isPayToScriptTemplate() {
    return this.type === $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToScriptTemplate;
  }
  /**
  * @return true if an address is a group token address
  */
  isGroupIdentifierAddress() {
    return this.type === $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.GroupIdAddress;
  }
  /**
  * Will return a validation error if exists
  *
  * @example
  * ```javascript
  * // a network mismatch error
  * let error = Address.getValidationError('nexatest:nqtsq5g567x44x5g54t2wsxz60zwqmyks63rkrddl4stwnzu', 'testnet');
  * ```
  *
  * @param data The encoded data
  * @param network either a Network instance, 'mainnet', or 'testnet'
  * @param type The type of address: 'P2ST' or 'GROUP' or 'P2PKH'
  * @returns The corresponding error message
  */
  static getValidationError(data, network, type) {
    try {
      if ((0, isString)(data)) {
        let addr = $92cd415860c918d9$export$2e2bcd8739ae039.fromString(data);
        data = addr.data;
        if (network && (0, $a89918d61ea4dca0$export$f09b1917886389c3).get(network)?.prefix !== addr.network.prefix) throw new Error("Address has mismatched network type.");
        network = addr.network;
        if (type && type !== addr.type) throw new Error("Address has mismatched type.");
        type = addr.type;
      }
      this.validateParams(network, type);
      (0, $c889a5b1bdeeb100$export$2e2bcd8739ae039).encode((0, $a89918d61ea4dca0$export$f09b1917886389c3).get(network)?.prefix || (0, $a89918d61ea4dca0$export$f09b1917886389c3).defaultNetwork.prefix, type || (0, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2).PayToScriptTemplate, data);
    } catch (e) {
      return e;
    }
  }
  /**
  * Will return a boolean if an address is valid
  *
  * @example
  * ```javascript
  * assert(Address.isValid('nexa:nqtsq5g567x44x5g54t2wsxz60zwqmyks63rkrddsfq94pd2', 'mainned'));
  * ```
  *
  * @param data The encoded data
  * @param network either a Network instance, 'mainnet', or 'testnet'
  * @param type The type of address: 'P2ST' or 'GROUP' or 'P2PKH'
  * @returns true if valid
  */
  static isValid(data, network, type) {
    return !$92cd415860c918d9$export$2e2bcd8739ae039.getValidationError(data, network, type);
  }
  /**
  * Instantiate an address from a PublicKey instance
  *
  * @param pubkey the public key instance
  * @param network either a Network instance, 'mainnet' or 'testnet'
  * @param type address encoding type
  * @returns A new valid and frozen instance of an Address
  */
  static fromPublicKey(pubkey, network, type) {
    let data = this._transformPublicKey(pubkey, type);
    return new $92cd415860c918d9$export$2e2bcd8739ae039(data, network, type);
  }
  /**
  * Instantiate an address from a non grouped script template
  *
  * @param templateHash An instance of a template hash Buffer
  * @param constraintHash An instance of a constraint hash Buffer
  * @param visibleArgs An array of push-only args, or hex string represent script buffer, or Script with push args
  * @param network either a Network instance, 'mainnet' or 'testnet'
  * @returns A new valid and frozen instance of an Address
  */
  static fromScriptTemplate(templateHash, constraintHash, visibleArgs, network) {
    let data = $92cd415860c918d9$export$2e2bcd8739ae039._transformScriptTemplate(templateHash, constraintHash, visibleArgs);
    return new $92cd415860c918d9$export$2e2bcd8739ae039(data, network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToScriptTemplate);
  }
  /**
  * Internal function to transform a {@link PublicKey}
  */
  static _transformPublicKey(pubkey, type = $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToScriptTemplate) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(pubkey instanceof $246eb589bb078d6d$export$2e2bcd8739ae039, "Address must be an instance of PublicKey.");
    if (type === $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash) return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256ripemd160(pubkey.toBuffer());
    else if (type === $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToScriptTemplate) {
      let constraint = $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add(pubkey.toBuffer());
      let constraintHash = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256ripemd160(constraint.toBuffer());
      return $92cd415860c918d9$export$2e2bcd8739ae039._transformScriptTemplate($92c0719d4ab9ac45$export$393941f88fd16991.OP_1, constraintHash);
    } else throw new Error("type must be P2ST or P2PKH");
  }
  /**
  * Internal function to transform a Script Template params
  */
  static _transformScriptTemplate(templateHash, constraintHash, visibleArgs) {
    if (templateHash != $92c0719d4ab9ac45$export$393941f88fd16991.OP_1 && !$9f918c10ad4fef51$export$2e2bcd8739ae039.isHashBuffer(templateHash)) throw new TypeError("templateHash supplied is not a hash buffer or well-known OP_1.");
    if (constraintHash != $92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE && !$9f918c10ad4fef51$export$2e2bcd8739ae039.isHashBuffer(constraintHash)) throw new TypeError("constraintHash supplied is not a hash buffer or OP_FALSE.");
    let scriptTemplate = $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add($92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE).add(templateHash).add(constraintHash);
    if (visibleArgs) {
      if (isArray(visibleArgs)) visibleArgs.forEach((arg) => scriptTemplate.add(arg));
      else if (visibleArgs instanceof $90f45db77a786f2b$export$2e2bcd8739ae039) scriptTemplate.add(visibleArgs);
      else if ($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(visibleArgs)) scriptTemplate.add($90f45db77a786f2b$export$2e2bcd8739ae039.fromHex(visibleArgs));
    }
    return new $35852622c8c617e8$export$2e2bcd8739ae039().writeVarLengthBuf(scriptTemplate.toBuffer()).toBuffer();
  }
  /**
  * Will return the transaction output type by the address type
  * 
  * @param address as string
  * @returns 1 - Template, 0 - otherwise
  */
  static getOutputType(address) {
    return this.fromString(address).getOutputType();
  }
  /**
  * Will return the transaction output type by the address type
  * 
  * @returns 1 - Template, 0 - otherwise
  */
  getOutputType() {
    return this.isPayToScriptTemplate() ? 1 : 0;
  }
}
class $9e7155c0d97105d3$export$2e2bcd8739ae039 {
  /**
  * Instantiate a PrivateKey.
  * 
  * @param data The private key data
  * 
  * @remarks Better to use {@linkcode PrivateKey.from} method to init private key from various formats if the formart unknown.
  *
  * @example
  * ```ts
  * // generate a new random key
  * let key = new PrivateKey();
  *
  * // encode into wallet import format
  * let exported = key.toWIF();
  *
  * // instantiate from the exported (and saved) private key
  * let imported = PrivateKey.fromWIF(exported);
  * ```
  */
  constructor(data) {
    this.toObject = this.toJSON;
    if (data instanceof $9e7155c0d97105d3$export$2e2bcd8739ae039) return data;
    if (isNil(data)) data = {
      bn: $9e7155c0d97105d3$export$2e2bcd8739ae039._getRandomBN(),
      compressed: true,
      network: $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork
    };
    if (!$9e7155c0d97105d3$export$2e2bcd8739ae039._isPrivateKeyParams(data)) throw new TypeError("First argument is an unrecognized data type.");
    if (!data.bn || data.bn.cmp(new $5aa97aebe18a7924$export$2e2bcd8739ae039(0)) === 0) throw new TypeError("Number can not be equal to zero, undefined, null or false");
    if (!data.bn.lt($ba7e1a38972b2d09$export$2e2bcd8739ae039.getN())) throw new TypeError("Number must be less than N");
    this.bn = data.bn;
    this.compressed = isUndefined(data.compressed) ? true : data.compressed;
    this.network = data.network || $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork;
  }
  get publicKey() {
    return this.toPublicKey();
  }
  /**
  * Will return an address for the private key with its defined network
  * 
  * @param type - optional parameter specifying the desired type of the address.
  *  default {@link AddressType.PayToScriptTemplate}
  * 
  * @returns An address generated from the private key
  */
  toAddress(type = $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToScriptTemplate) {
    return $92cd415860c918d9$export$2e2bcd8739ae039.fromPublicKey(this.publicKey, this.network, type);
  }
  /**
  * Will output the PrivateKey encoded as hex string
  */
  toString() {
    return this.toBuffer().toString("hex");
  }
  /**
  * Will encode the PrivateKey to a WIF string
  *
  * @returns A WIF representation of the private key
  */
  toWIF() {
    let buf;
    if (this.compressed) buf = Buffer$1.concat([
      Buffer$1.from([
        this.network.privatekey
      ]),
      this.bn.toBuffer({
        size: 32
      }),
      Buffer$1.from([
        1
      ])
    ]);
    else buf = Buffer$1.concat([
      Buffer$1.from([
        this.network.privatekey
      ]),
      this.bn.toBuffer({
        size: 32
      })
    ]);
    return $7daa49d6586b1e1a$export$2e2bcd8739ae039.encode(buf);
  }
  /**
  * Will return the private key as a BN instance
  *
  * @returns A BN instance of the private key
  */
  toBigNumber() {
    return this.bn;
  }
  /**
  * Will return the private key as a BN buffer
  *
  * @returns A buffer of the private key
  */
  toBuffer() {
    return this.bn.toBuffer({
      size: 32
    });
  }
  /**
  * Will return the private key as a BN buffer without leading zero padding
  *
  * @returns A buffer of the private key
  */
  toBufferNoPadding() {
    return this.bn.toBuffer();
  }
  /**
  * Will return the corresponding public key
  *
  * @returns A public key generated from the private key
  */
  toPublicKey() {
    if (!this._pubkey) this._pubkey = $246eb589bb078d6d$export$2e2bcd8739ae039.fromPrivateKey(this);
    return this._pubkey;
  }
  /**
  * @returns A plain object representation
  */
  toJSON() {
    return {
      bn: this.bn.toString("hex"),
      compressed: this.compressed,
      network: this.network.toString()
    };
  }
  /**
  * Will return a string formatted for the console
  *
  * @returns Private key details
  */
  inspect() {
    let uncompressed = !this.compressed ? ", uncompressed" : "";
    return `<PrivateKey: ${this.toString()}, network: ${this.network}${uncompressed}>`;
  }
  /**
  * Instantiate a PrivateKey from a Buffer with the DER or WIF representation
  */
  static fromBuffer(buf, network) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "First argument is expected to be a buffer.");
    let data = this._transformBuffer(buf, network);
    return new $9e7155c0d97105d3$export$2e2bcd8739ae039(data);
  }
  static {
    this.fromString = this.fromWIF;
  }
  /**
  * Instantiate a PrivateKey from a WIF string
  *
  * @param str - The WIF encoded private key string
  * @returns A new valid instance of PrivateKey
  */
  static fromWIF(str, network) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(str), "First argument is expected to be a string.");
    let data;
    if ($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(str)) data = {
      bn: new $5aa97aebe18a7924$export$2e2bcd8739ae039(Buffer$1.from(str, "hex")),
      compressed: true,
      network: $a89918d61ea4dca0$export$f09b1917886389c3.get(network) || $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork
    };
    else data = $9e7155c0d97105d3$export$2e2bcd8739ae039._transformWIF(str, network);
    return new $9e7155c0d97105d3$export$2e2bcd8739ae039(data);
  }
  static {
    this.fromObject = this.fromJSON;
  }
  /**
  * Instantiate a PrivateKey from a plain JavaScript object
  *
  * @param obj - The output from privateKey.toObject()
  */
  static fromJSON(obj) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(obj), "First argument is expected to be an object.");
    let data = this._transformObject(obj);
    return new $9e7155c0d97105d3$export$2e2bcd8739ae039(data);
  }
  /**
  * Instantiate a PrivateKey from random bytes
  *
  * @param network - Either "mainnet" or "testnet"
  * @returns A new valid instance of PrivateKey
  */
  static fromRandom(network) {
    let data = {
      bn: $9e7155c0d97105d3$export$2e2bcd8739ae039._getRandomBN(),
      compressed: true,
      network: $a89918d61ea4dca0$export$f09b1917886389c3.get(network) || $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork
    };
    return new $9e7155c0d97105d3$export$2e2bcd8739ae039(data);
  }
  /**
  * Check if there would be any errors when initializing a PrivateKey
  *
  * @param data - The encoded data in various formats
  * @param network - Either "mainnet" or "testnet"
  * @returns An error if exists
  */
  static getValidationError(data, network) {
    try {
      this.from(data, network);
    } catch (e) {
      return e;
    }
    return void 0;
  }
  /**
  * Check if the parameters are valid
  *
  * @param data - The encoded data in various formats
  * @param network - Either "mainnet" or "testnet"
  * @returns true If the private key would be valid
  */
  static isValid(data, network) {
    if (!data) return false;
    return !this.getValidationError(data, network);
  }
  /**
  * Helper to instantiate PrivateKey from different kinds of arguments.
  */
  static from(data, network) {
    if (isNil(data)) return this.fromRandom(network);
    else if (data instanceof $9e7155c0d97105d3$export$2e2bcd8739ae039) return data;
    else if (data instanceof $5aa97aebe18a7924$export$2e2bcd8739ae039) {
      let info = {
        bn: data,
        compressed: true,
        network: $a89918d61ea4dca0$export$f09b1917886389c3.get(network) || $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork
      };
      return new $9e7155c0d97105d3$export$2e2bcd8739ae039(info);
    } else if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(data)) return this.fromBuffer(data, network);
    else if (this._isPrivateKeyParams(data) && data.bn && data.network) return this.fromObject(data);
    else if (isString(data)) return this.fromString(data, network);
    else throw new TypeError("First argument is an unrecognized data type.");
  }
  static _isPrivateKeyParams(data) {
    return isObject$1(data) && "bn" in data && "network" in data;
  }
  static _getRandomBN() {
    let bn;
    do {
      let privbuf = $9f918c10ad4fef51$export$2e2bcd8739ae039.getRandomBuffer(32);
      bn = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(privbuf);
    } while (!bn.lt($ba7e1a38972b2d09$export$2e2bcd8739ae039.getN()));
    return bn;
  }
  /**
  * Internal function to transform a WIF Buffer into a private key
  */
  static _transformBuffer(buf, network) {
    if (buf.length === 32) return {
      network: $a89918d61ea4dca0$export$f09b1917886389c3.get(network) || $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork,
      bn: $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(buf),
      compressed: false
    };
    let info = {};
    info.network = $a89918d61ea4dca0$export$f09b1917886389c3.get(buf[0], "privatekey");
    if (!info.network) throw new Error(`Invalid network`);
    if (network && info.network !== $a89918d61ea4dca0$export$f09b1917886389c3.get(network)) throw new TypeError("Private key network mismatch");
    if (buf.length === 34 && buf[33] === 1) info.compressed = true;
    else if (buf.length === 33) info.compressed = false;
    else throw new Error("Length of buffer must be 33 (uncompressed) or 34 (compressed)");
    info.bn = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(buf.subarray(1, 33));
    return info;
  }
  /**
  * Internal function to transform a JSON object into a private key
  */
  static _transformObject(data) {
    return {
      bn: new $5aa97aebe18a7924$export$2e2bcd8739ae039(data.bn, "hex"),
      network: $a89918d61ea4dca0$export$f09b1917886389c3.get(data.network) || $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork,
      compressed: data.compressed
    };
  }
  /**
  * Internal function to transform a WIF string into a private key
  */
  static _transformWIF(str, network) {
    return this._transformBuffer($7daa49d6586b1e1a$export$2e2bcd8739ae039.decode(str), network);
  }
}
class $824be92afb10ca74$export$b9181e523c619f72 extends Error {
  constructor(arg) {
    super(`Invalid derivation argument: got ${arg}`);
  }
}
class $824be92afb10ca74$export$b59b0d37c3755b05 extends Error {
  constructor(arg) {
    super(`Invalid derivation path, it should look like: "m/1/100", got "${arg}"`);
  }
}
class $824be92afb10ca74$export$f3983d7477e5f2f4 extends Error {
  constructor(char, data) {
    super(`Invalid Base58 character: ${char} in ${data}`);
  }
}
class $824be92afb10ca74$export$11fc854522c14d8d extends Error {
  constructor(arg) {
    super(`Invalid Base58 checksum for ${arg}`);
  }
}
class $824be92afb10ca74$export$e84f5e0e00fb0c4b extends Error {
  constructor(arg) {
    super(`Invalid length for xprivkey string in ${arg}`);
  }
}
class $824be92afb10ca74$export$a1d2727a53328ff extends Error {
  constructor(arg) {
    super(`Invalid version for network: got ${arg}`);
  }
}
class $824be92afb10ca74$export$7f451ba410ad3fb extends Error {
  constructor(arg) {
    super(`Invalid network: must be "mainnet" or "testnet", got ${arg}`);
  }
}
class $824be92afb10ca74$export$c8ad90567a3adc29 extends Error {
  constructor(arg) {
    super(`Invalid entropy: must be an hexa string or binary buffer, got ${arg}`);
  }
}
class $824be92afb10ca74$export$136e7f0d62b8ef6f extends Error {
  constructor(arg) {
    super(`Invalid entropy: more than 512 bits is non standard, got ${arg}`);
  }
}
class $824be92afb10ca74$export$18f1c215e936cdfa extends Error {
  constructor(arg) {
    super(`Invalid entropy: at least 128 bits needed, got ${arg}`);
  }
}
class $824be92afb10ca74$export$f1e27c60caf56b0a extends Error {
  constructor() {
    super(`Argument is an extended private key`);
  }
}
class $824be92afb10ca74$export$1efb2ac49bec6b75 extends Error {
  constructor() {
    super(`Invalid argument: creating a hardened path requires an HDPrivateKey`);
  }
}
class $850698057fd6f95c$export$2e2bcd8739ae039 {
  static {
    this.Hardened = 2147483648;
  }
  static {
    this.MaxIndex = 2 * $850698057fd6f95c$export$2e2bcd8739ae039.Hardened;
  }
  static {
    this.RootElementAlias = [
      "m",
      "M",
      "m'",
      "M'"
    ];
  }
  static {
    this.VersionSize = 4;
  }
  static {
    this.DepthSize = 1;
  }
  static {
    this.ParentFingerPrintSize = 4;
  }
  static {
    this.ChildIndexSize = 4;
  }
  static {
    this.ChainCodeSize = 32;
  }
  static {
    this.CheckSumSize = 4;
  }
  static {
    this.DataSize = 78;
  }
  static {
    this.SerializedByteSize = 82;
  }
  static {
    this.VersionStart = 0;
  }
  static {
    this.VersionEnd = $850698057fd6f95c$export$2e2bcd8739ae039.VersionStart + $850698057fd6f95c$export$2e2bcd8739ae039.VersionSize;
  }
  static {
    this.DepthStart = $850698057fd6f95c$export$2e2bcd8739ae039.VersionEnd;
  }
  static {
    this.DepthEnd = $850698057fd6f95c$export$2e2bcd8739ae039.DepthStart + $850698057fd6f95c$export$2e2bcd8739ae039.DepthSize;
  }
  static {
    this.ParentFingerPrintStart = $850698057fd6f95c$export$2e2bcd8739ae039.DepthEnd;
  }
  static {
    this.ParentFingerPrintEnd = $850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintStart + $850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintSize;
  }
  static {
    this.ChildIndexStart = $850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintEnd;
  }
  static {
    this.ChildIndexEnd = $850698057fd6f95c$export$2e2bcd8739ae039.ChildIndexStart + $850698057fd6f95c$export$2e2bcd8739ae039.ChildIndexSize;
  }
  static {
    this.ChainCodeStart = $850698057fd6f95c$export$2e2bcd8739ae039.ChildIndexEnd;
  }
  static {
    this.ChainCodeEnd = $850698057fd6f95c$export$2e2bcd8739ae039.ChainCodeStart + $850698057fd6f95c$export$2e2bcd8739ae039.ChainCodeSize;
  }
  /**
  * Util function that splits a string path into a derivation index array.
  * It will return null if the string path is malformed.
  * It does not validate if indexes are in bounds.
  *
  * @param path
  */
  static getDerivationIndexes(path) {
    if (this.RootElementAlias.includes(path)) return [];
    let steps = path.split("/");
    if (!this.RootElementAlias.includes(steps[0])) return null;
    let indexes = steps.slice(1).map((step) => {
      let isHardened = step.slice(-1) === "'";
      if (isHardened) step = step.slice(0, -1);
      if (!step || step[0] === "-") return NaN;
      let index = +step;
      if (isHardened) index += this.Hardened;
      return index;
    });
    return indexes.some(isNaN) ? null : indexes;
  }
  static _validateNetwork(data, networkArg, isPrivate = false) {
    let network = $a89918d61ea4dca0$export$f09b1917886389c3.get(networkArg);
    if (!network) return new $824be92afb10ca74$export$7f451ba410ad3fb(networkArg);
    let version = data.subarray(this.VersionStart, this.VersionEnd);
    if ($9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(version) !== (isPrivate ? network.xprivkey : network.xpubkey)) return new $824be92afb10ca74$export$a1d2727a53328ff(version);
    return null;
  }
  /**
  * Verifies that a given serialized hd key in base58 with checksum format
  * is valid.
  *
  * @param data - the serialized hd key
  * @param network - optional, if present, checks that the network provided matches the network serialized.
  */
  static isValidSerialized(data, network, isPrivate = false) {
    return isNull(this.getSerializedError(data, network, isPrivate));
  }
  /**
  * Checks what's the error that causes the validation of a serialized public key
  * in base58 with checksum to fail.
  *
  * @param data - the serialized hd key
  * @param network - optional, if present, checks that the network provided matches the network serialized.
  */
  static getSerializedError(data, network, isPrivate = false) {
    if (!(isString(data) || $9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(data))) return new TypeError("Expected string or buffer");
    if (!$5d1fb851ba849ee0$export$2e2bcd8739ae039.validCharacters(data)) return new $824be92afb10ca74$export$f3983d7477e5f2f4("(unknown)", data);
    try {
      data = (0, $7daa49d6586b1e1a$export$2e2bcd8739ae039).decode(data);
    } catch {
      return new $824be92afb10ca74$export$11fc854522c14d8d(data);
    }
    if (data.length !== $850698057fd6f95c$export$2e2bcd8739ae039.DataSize) return new $824be92afb10ca74$export$e84f5e0e00fb0c4b(data);
    if (!isUndefined(network)) {
      let error = this._validateNetwork(data, network, isPrivate);
      if (error) return error;
    }
    if (!isPrivate) {
      let version = $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(data.subarray(0, 4));
      if (version === $a89918d61ea4dca0$export$f09b1917886389c3.mainnet.xprivkey || version === $a89918d61ea4dca0$export$f09b1917886389c3.testnet.xprivkey) return new $824be92afb10ca74$export$f1e27c60caf56b0a();
    }
    return null;
  }
}
class $ef69ee312dbfbba6$export$2e2bcd8739ae039 {
  static {
    this.PublicKeySize = 33;
  }
  static {
    this.PublicKeyStart = $850698057fd6f95c$export$2e2bcd8739ae039.ChainCodeEnd;
  }
  static {
    this.PublicKeyEnd = this.PublicKeyStart + this.PublicKeySize;
  }
  static {
    this.ChecksumStart = this.PublicKeyEnd;
  }
  static {
    this.ChecksumEnd = this.ChecksumStart + $850698057fd6f95c$export$2e2bcd8739ae039.CheckSumSize;
  }
  /**
  * The representation of an hierarchically derived public key.
  *
  * See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  *
  * @param arg
  */
  constructor(arg) {
    this.toJSON = this.toObject;
    if (isNil(arg)) throw new TypeError("Must supply an argument to create a HDPublicKey");
    if (arg instanceof $ef69ee312dbfbba6$export$2e2bcd8739ae039) return arg;
    let params = $ef69ee312dbfbba6$export$2e2bcd8739ae039._classifyArgument(arg);
    this.publicKey = params.publicKey;
    this.network = params.network;
    this.depth = params.depth;
    this.parentFingerPrint = params.parentFingerPrint;
    this.fingerPrint = params.fingerPrint;
    this.chainCode = params.chainCode;
    this.childIndex = params.childIndex;
    this.xpubkey = params.xpubkey;
    this.checksum = params.checksum;
  }
  static _classifyArgument(arg) {
    if (isString(arg) || $9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(arg)) {
      let xpubkey = arg.toString();
      if ($850698057fd6f95c$export$2e2bcd8739ae039.isValidSerialized(xpubkey)) return this._buildFromSerialized(xpubkey);
      throw $850698057fd6f95c$export$2e2bcd8739ae039.getSerializedError(arg);
    }
    if (this._isIHDPubKey(arg)) return arg;
    if (this._isMinimalDtoObject(arg)) return this._buildFromMinimalObject(arg);
    if (this._isDtoObject(arg)) return this._buildFromObject(arg);
    if (this._isIHDPrivKey(arg)) return this._buildFromHDPrivateKey(arg);
    throw new TypeError("Invalid argument type for creation, must be string, json, buffer, or object");
  }
  static _isDtoObject(data) {
    return isObject$1(data) && "xpubkey" in data && !("privateKey" in data) && "publicKey" in data && isString(data.publicKey);
  }
  static _isMinimalDtoObject(data) {
    return isObject$1(data) && !("xpubkey" in data) && !("privateKey" in data) && "publicKey" in data && isString(data.publicKey);
  }
  static _isIHDPubKey(data) {
    return isObject$1(data) && "xpubkey" in data && !("privateKey" in data) && "publicKey" in data && data.publicKey instanceof $246eb589bb078d6d$export$2e2bcd8739ae039;
  }
  static _isIHDPrivKey(data) {
    return isObject$1(data) && "privateKey" in data && isObject$1(data.privateKey) && "bn" in data.privateKey;
  }
  /**
  * Verifies that a given path is valid.
  *
  * @param arg
  * @return {boolean}
  */
  static isValidPath(arg) {
    if (isString(arg)) {
      let indexes = $850698057fd6f95c$export$2e2bcd8739ae039.getDerivationIndexes(arg);
      return indexes !== null && indexes.every($ef69ee312dbfbba6$export$2e2bcd8739ae039.isValidPath);
    }
    if (isNumber$1(arg)) return arg >= 0 && arg < $850698057fd6f95c$export$2e2bcd8739ae039.Hardened;
    return false;
  }
  /**
  * Create a HDPublicKey from a buffer argument
  *
  * @param buf
  */
  static fromBuffer(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "No valid Buffer was provided");
    return new $ef69ee312dbfbba6$export$2e2bcd8739ae039(buf);
  }
  /**
  * Return a buffer representation of the xpubkey
  */
  toBuffer() {
    return Buffer$1.from(this.xpubkey);
  }
  static fromString(xpubkey) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(xpubkey), "No valid string was provided");
    return new $ef69ee312dbfbba6$export$2e2bcd8739ae039(xpubkey);
  }
  /**
  * Returns the base58 checked representation of the public key
  * @return a string starting with "xpub..." in livenet
  */
  toString() {
    return this.xpubkey;
  }
  /**
  * Returns the console representation of this extended public key.
  */
  inspect() {
    return `<HDPublicKey: ${this}>`;
  }
  static fromObject(arg) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(arg), "No valid argument was provided");
    return new $ef69ee312dbfbba6$export$2e2bcd8739ae039(arg);
  }
  static fromMinimalObject(arg) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(arg), "No valid argument was provided");
    let params = this._buildFromMinimalObject(arg);
    return new $ef69ee312dbfbba6$export$2e2bcd8739ae039(params);
  }
  /**
  * Returns a plain JavaScript object with information to reconstruct a key.
  */
  toObject() {
    return {
      network: this.network.name,
      depth: this.depth,
      fingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(this.fingerPrint),
      parentFingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(this.parentFingerPrint),
      childIndex: this.childIndex,
      chainCode: this.chainCode.toString("hex"),
      publicKey: this.publicKey.toString(),
      checksum: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(this.checksum),
      xpubkey: this.xpubkey
    };
  }
  /**
  * Will return an address for the hdpubkey with its defined network
  * 
  * @param type - optional parameter specifying the desired type of the address.
  *  default {@link AddressType.PayToScriptTemplate}
  * 
  * @returns An address generated from the hd public key
  */
  toAddress(type = $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToScriptTemplate) {
    return $92cd415860c918d9$export$2e2bcd8739ae039.fromPublicKey(this.publicKey, this.network, type);
  }
  /**
  * Get a derivated child based on a string or number.
  *
  * If the first argument is a string, it's parsed as the full path of
  * derivation. Valid values for this argument include "m" (which returns the
  * same public key), "m/0/1/40/2/1000".
  *
  * Note that hardened keys can't be derived from a public extended key.
  *
  * If the first argument is a number, the child with that index will be
  * derived. See the example usage for clarification.
  *
  * @example
  * ```javascript
  * let parent = new HDPublicKey('xpub...');
  * let child_0_1_2 = parent.deriveChild(0).deriveChild(1).deriveChild(2);
  * let copy_of_child_0_1_2 = parent.deriveChild("m/0/1/2");
  * assert(child_0_1_2.xpubkey === copy_of_child_0_1_2.xpubkey);
  * ```
  *
  * @param {string|number} arg
  */
  deriveChild(arg, hardened) {
    if (isNumber$1(arg)) return this._deriveWithNumber(arg, hardened);
    if (isString(arg)) return this._deriveFromString(arg);
    throw new $824be92afb10ca74$export$b9181e523c619f72(arg);
  }
  _deriveWithNumber(index, hardened) {
    if (index >= $850698057fd6f95c$export$2e2bcd8739ae039.Hardened || hardened) throw new $824be92afb10ca74$export$1efb2ac49bec6b75();
    if (index < 0) throw new $824be92afb10ca74$export$b59b0d37c3755b05(index);
    let indexBuffer = $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(index);
    let data = Buffer$1.concat([
      this.publicKey.toBuffer(),
      indexBuffer
    ]);
    let hash = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha512hmac(data, this.chainCode);
    let leftPart = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(hash.subarray(0, 32), {
      size: 32
    });
    let chainCode = hash.subarray(32, 64);
    let publicKey;
    try {
      publicKey = (0, $246eb589bb078d6d$export$2e2bcd8739ae039).fromPoint((0, $ba7e1a38972b2d09$export$2e2bcd8739ae039).getG().mul(leftPart).add(this.publicKey.point));
    } catch {
      return this._deriveWithNumber(index + 1);
    }
    let buffers = {
      version: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(this.network.xpubkey),
      depth: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsSingleByteBuffer(this.depth + 1),
      parentFingerPrint: this.fingerPrint,
      childIndex: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(index),
      publicKey: publicKey.toBuffer(),
      chainCode
    };
    let derived = $ef69ee312dbfbba6$export$2e2bcd8739ae039._buildFromBuffers(buffers);
    return new $ef69ee312dbfbba6$export$2e2bcd8739ae039(derived);
  }
  _deriveFromString(path) {
    if (path.includes("'")) throw new $824be92afb10ca74$export$1efb2ac49bec6b75();
    if (!$ef69ee312dbfbba6$export$2e2bcd8739ae039.isValidPath(path)) throw new $824be92afb10ca74$export$b59b0d37c3755b05(path);
    const deriveKeys = (baseKey, indexes2) => {
      return indexes2.reduce((prev, idx) => prev._deriveWithNumber(idx), baseKey);
    };
    let indexes = $850698057fd6f95c$export$2e2bcd8739ae039.getDerivationIndexes(path);
    return deriveKeys(this, indexes);
  }
  static _buildFromObject(arg) {
    return {
      network: $a89918d61ea4dca0$export$f09b1917886389c3.get(arg.network),
      depth: arg.depth,
      fingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(arg.fingerPrint),
      parentFingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(arg.parentFingerPrint),
      childIndex: arg.childIndex,
      chainCode: Buffer$1.from(arg.chainCode, "hex"),
      xpubkey: arg.xpubkey,
      checksum: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(arg.checksum),
      publicKey: $246eb589bb078d6d$export$2e2bcd8739ae039.fromString(arg.publicKey, void 0, $a89918d61ea4dca0$export$f09b1917886389c3.get(arg.network))
    };
  }
  static _buildFromMinimalObject(arg) {
    let buffers = {
      version: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer($a89918d61ea4dca0$export$f09b1917886389c3.get(arg.network).xpubkey),
      depth: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsSingleByteBuffer(arg.depth),
      parentFingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(arg.parentFingerPrint),
      childIndex: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(arg.childIndex),
      chainCode: Buffer$1.from(arg.chainCode, "hex"),
      publicKey: Buffer$1.from(arg.publicKey, "hex")
    };
    return this._buildFromBuffers(buffers);
  }
  static _buildFromHDPrivateKey(hdPrivateKey) {
    let point = $ba7e1a38972b2d09$export$2e2bcd8739ae039.getG().mul(hdPrivateKey.privateKey.bn);
    let buffers = {
      version: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(hdPrivateKey.network.xpubkey),
      depth: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsSingleByteBuffer(hdPrivateKey.depth),
      parentFingerPrint: hdPrivateKey.parentFingerPrint,
      childIndex: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(hdPrivateKey.childIndex),
      chainCode: hdPrivateKey.chainCode,
      publicKey: $ba7e1a38972b2d09$export$2e2bcd8739ae039.pointToCompressed(point)
    };
    return this._buildFromBuffers(buffers);
  }
  static _buildFromSerialized(xpubkey) {
    let decoded = $7daa49d6586b1e1a$export$2e2bcd8739ae039.decode(xpubkey);
    let buffers = {
      version: decoded.subarray($850698057fd6f95c$export$2e2bcd8739ae039.VersionStart, $850698057fd6f95c$export$2e2bcd8739ae039.VersionEnd),
      depth: decoded.subarray($850698057fd6f95c$export$2e2bcd8739ae039.DepthStart, $850698057fd6f95c$export$2e2bcd8739ae039.DepthEnd),
      parentFingerPrint: decoded.subarray($850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintStart, $850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintEnd),
      childIndex: decoded.subarray($850698057fd6f95c$export$2e2bcd8739ae039.ChildIndexStart, $850698057fd6f95c$export$2e2bcd8739ae039.ChildIndexEnd),
      chainCode: decoded.subarray($850698057fd6f95c$export$2e2bcd8739ae039.ChainCodeStart, $850698057fd6f95c$export$2e2bcd8739ae039.ChainCodeEnd),
      publicKey: decoded.subarray(this.PublicKeyStart, this.PublicKeyEnd),
      checksum: decoded.subarray(this.ChecksumStart, this.ChecksumEnd)
    };
    return this._buildFromBuffers(buffers);
  }
  /**
  * Receives a object with buffers in all the properties and populates the
  * internal structure
  *
  * @param arg
  */
  static _buildFromBuffers(arg) {
    $ef69ee312dbfbba6$export$2e2bcd8739ae039._validateBufferArguments(arg);
    let sequence = [
      arg.version,
      arg.depth,
      arg.parentFingerPrint,
      arg.childIndex,
      arg.chainCode,
      arg.publicKey
    ];
    let concat = Buffer$1.concat(sequence);
    let checksum = $7daa49d6586b1e1a$export$2e2bcd8739ae039.checksum(concat);
    if (!arg.checksum || !arg.checksum.length) arg.checksum = checksum;
    else if (arg.checksum.toString("hex") !== checksum.toString("hex")) throw new $824be92afb10ca74$export$11fc854522c14d8d(concat);
    let network = $a89918d61ea4dca0$export$f09b1917886389c3.get($9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(arg.version));
    let publicKey = $246eb589bb078d6d$export$2e2bcd8739ae039.fromBuffer(arg.publicKey, true, network);
    return {
      xpubkey: $7daa49d6586b1e1a$export$2e2bcd8739ae039.encode(concat),
      network,
      depth: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromSingleByteBuffer(arg.depth),
      publicKey,
      fingerPrint: $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256ripemd160(publicKey.toBuffer()).subarray(0, $850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintSize),
      chainCode: arg.chainCode,
      childIndex: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(arg.childIndex),
      parentFingerPrint: arg.parentFingerPrint,
      checksum: arg.checksum
    };
  }
  static _validateBufferArguments(arg) {
    const checkBuffer = (name, size) => {
      let buff = arg[name];
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buff), name + ` argument is not a buffer, it's ${typeof buff}`);
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(buff.length === size, name + " has not the expected size: found " + buff.length + ", expected " + size);
    };
    checkBuffer("version", $850698057fd6f95c$export$2e2bcd8739ae039.VersionSize);
    checkBuffer("depth", $850698057fd6f95c$export$2e2bcd8739ae039.DepthSize);
    checkBuffer("parentFingerPrint", $850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintSize);
    checkBuffer("childIndex", $850698057fd6f95c$export$2e2bcd8739ae039.ChildIndexSize);
    checkBuffer("chainCode", $850698057fd6f95c$export$2e2bcd8739ae039.ChainCodeSize);
    checkBuffer("publicKey", $ef69ee312dbfbba6$export$2e2bcd8739ae039.PublicKeySize);
    if (arg.checksum?.length) checkBuffer("checksum", $850698057fd6f95c$export$2e2bcd8739ae039.CheckSumSize);
  }
}
class $8fc74ca0a6995b3b$export$2e2bcd8739ae039 {
  static {
    this.MINIMUM_ENTROPY_BITS = 128;
  }
  static {
    this.BITS_TO_BYTES = 1 / 8;
  }
  static {
    this.MAXIMUM_ENTROPY_BITS = 512;
  }
  static {
    this.PrivateKeySize = 32;
  }
  static {
    this.PrivateKeyStart = $850698057fd6f95c$export$2e2bcd8739ae039.ChainCodeEnd + 1;
  }
  static {
    this.PrivateKeyEnd = this.PrivateKeyStart + this.PrivateKeySize;
  }
  static {
    this.ChecksumStart = this.PrivateKeyEnd;
  }
  static {
    this.ChecksumEnd = this.ChecksumStart + $850698057fd6f95c$export$2e2bcd8739ae039.CheckSumSize;
  }
  /**
  * Represents an instance of an hierarchically derived private key.
  *
  * More info on https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  */
  constructor(arg) {
    this.toJSON = this.toObject;
    if (arg instanceof $8fc74ca0a6995b3b$export$2e2bcd8739ae039) return arg;
    let params = $8fc74ca0a6995b3b$export$2e2bcd8739ae039._classifyArgument(arg);
    this.privateKey = params.privateKey;
    this.publicKey = params.publicKey ?? params.privateKey.toPublicKey();
    this.network = params.network;
    this.depth = params.depth;
    this.parentFingerPrint = params.parentFingerPrint;
    this.fingerPrint = params.fingerPrint;
    this.chainCode = params.chainCode;
    this.childIndex = params.childIndex;
    this.xprivkey = params.xprivkey;
    this.checksum = params.checksum;
  }
  static _classifyArgument(arg) {
    if (!arg) return this._generateRandomly();
    if ($a89918d61ea4dca0$export$f09b1917886389c3.get(arg)) return this._generateRandomly(arg);
    if (isString(arg) || $9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(arg)) {
      let xprivkey = arg.toString();
      if ($850698057fd6f95c$export$2e2bcd8739ae039.isValidSerialized(xprivkey, void 0, true)) return this._buildFromSerialized(xprivkey);
      if ($c337f7a9455509cf$export$2e2bcd8739ae039.isValidJSON(arg)) return this._buildFromObject(JSON.parse(arg));
      throw $850698057fd6f95c$export$2e2bcd8739ae039.getSerializedError(arg, void 0, true);
    }
    if (this._isIHDPrivKey(arg)) return arg;
    if (this._isMinimalDtoObject(arg)) return this._buildFromMinimalObject(arg);
    if (this._isDtoObject(arg)) return this._buildFromObject(arg);
    throw new TypeError("Invalid argument type for creation, must be string, json, buffer, or object");
  }
  get hdPublicKey() {
    return this.getHDPublicKey();
  }
  get xpubkey() {
    return this.getHDPublicKey().xpubkey;
  }
  static _isDtoObject(data) {
    return isObject$1(data) && "xprivkey" in data && "privateKey" in data && isString(data.privateKey);
  }
  static _isMinimalDtoObject(data) {
    return isObject$1(data) && !("xprivkey" in data) && "privateKey" in data && isString(data.privateKey);
  }
  static _isIHDPrivKey(data) {
    return isObject$1(data) && "xprivkey" in data && "privateKey" in data && data.privateKey instanceof $9e7155c0d97105d3$export$2e2bcd8739ae039;
  }
  /**
  * Verifies that a given path is valid.
  *
  * @param arg
  * @param hardened
  */
  static isValidPath(arg, hardened) {
    if (isString(arg)) {
      let indexes = $850698057fd6f95c$export$2e2bcd8739ae039.getDerivationIndexes(arg);
      return indexes !== null && indexes.every((i) => this.isValidPath(i));
    }
    if (isNumber$1(arg)) {
      if (arg < $850698057fd6f95c$export$2e2bcd8739ae039.Hardened && hardened === true) arg += $850698057fd6f95c$export$2e2bcd8739ae039.Hardened;
      return arg >= 0 && arg < $850698057fd6f95c$export$2e2bcd8739ae039.MaxIndex;
    }
    return false;
  }
  static fromString(xprivkey) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(xprivkey), "No valid string was provided");
    return new $8fc74ca0a6995b3b$export$2e2bcd8739ae039(xprivkey);
  }
  /**
  * Returns the string representation of this private key (ext privkey).
  */
  toString() {
    return this.xprivkey;
  }
  /**
  * Build a HDPrivateKey from a buffer
  *
  * @param {Buffer} buf
  */
  static fromBuffer(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "No valid Buffer was provided");
    return new $8fc74ca0a6995b3b$export$2e2bcd8739ae039(buf);
  }
  /**
  * Returns a buffer representation of the HDPrivateKey
  */
  toBuffer() {
    return Buffer$1.from(this.xprivkey);
  }
  /**
  * Returns a plain object with a representation of this private key.
  */
  toObject() {
    return {
      network: this.network.name,
      depth: this.depth,
      fingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(this.fingerPrint),
      parentFingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(this.parentFingerPrint),
      childIndex: this.childIndex,
      chainCode: this.chainCode.toString("hex"),
      privateKey: this.privateKey.toString(),
      checksum: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(this.checksum),
      xprivkey: this.xprivkey
    };
  }
  static fromObject(arg) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(arg), "No valid argument was provided");
    return new $8fc74ca0a6995b3b$export$2e2bcd8739ae039(arg);
  }
  static fromMinimalObject(arg) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(arg), "No valid argument was provided");
    let params = this._buildFromMinimalObject(arg);
    return new $8fc74ca0a6995b3b$export$2e2bcd8739ae039(params);
  }
  /**
  * Generate a private key from a seed, as described in BIP32
  *
  * @param seed
  * @param network
  * @return HDPrivateKey
  */
  static fromSeed(seed, network = $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork) {
    let params = this._buildFromSeed(seed, network);
    return new $8fc74ca0a6995b3b$export$2e2bcd8739ae039(params);
  }
  /**
  * Get a derived child based on a string or number.
  *
  * If the first argument is a string, it's parsed as the full path of
  * derivation. Valid values for this argument include "m" (which returns the
  * same private key), "m/0/1/40/2'/1000", where the ' quote means a hardened
  * derivation.
  *
  * If the first argument is a number, the child with that index will be
  * derived. If the second argument is truthy, the hardened version will be
  * derived. See the example usage for clarification.
  *
  * @example
  * ```javascript
  * let parent = new HDPrivateKey('xprv...');
  * let child_0_1_2h = parent.deriveChild(0).deriveChild(1).deriveChild(2, true);
  * let copy_of_child_0_1_2h = parent.deriveChild("m/0/1/2'");
  * assert(child_0_1_2h.xprivkey === copy_of_child_0_1_2h.xprivkey);
  * ```
  *
  * @param arg
  * @param hardened
  * @return HDPrivateKey
  */
  deriveChild(arg, hardened) {
    if (isNumber$1(arg)) return this._deriveWithNumber(arg, hardened);
    if (isString(arg)) return this._deriveFromString(arg);
    throw new $824be92afb10ca74$export$b9181e523c619f72(arg);
  }
  _deriveWithNumber(index, hardened) {
    if (!$8fc74ca0a6995b3b$export$2e2bcd8739ae039.isValidPath(index, hardened)) throw new $824be92afb10ca74$export$b59b0d37c3755b05(index);
    hardened = index >= $850698057fd6f95c$export$2e2bcd8739ae039.Hardened ? true : hardened;
    if (index < $850698057fd6f95c$export$2e2bcd8739ae039.Hardened && hardened === true) index += $850698057fd6f95c$export$2e2bcd8739ae039.Hardened;
    let indexBuffer = $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(index);
    let data;
    if (hardened) {
      let privateKeyBuffer = this.privateKey.toBuffer();
      $e44f707fde477092$export$2e2bcd8739ae039.validateState(privateKeyBuffer.length === 32, "length of private key buffer is expected to be 32 bytes");
      data = Buffer$1.concat([
        Buffer$1.from([
          0
        ]),
        privateKeyBuffer,
        indexBuffer
      ]);
    } else data = Buffer$1.concat([
      this.publicKey.toBuffer(),
      indexBuffer
    ]);
    let hash = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha512hmac(data, this.chainCode);
    let leftPart = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(hash.subarray(0, 32), {
      size: 32
    });
    let chainCode = hash.subarray(32, 64);
    let privateKey = leftPart.add(this.privateKey.toBigNumber()).umod($ba7e1a38972b2d09$export$2e2bcd8739ae039.getN()).toBuffer({
      size: 32
    });
    if (!$9e7155c0d97105d3$export$2e2bcd8739ae039.isValid(privateKey))
      return this._deriveWithNumber(index + 1);
    let buffers = {
      version: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(this.network.xprivkey),
      depth: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsSingleByteBuffer(this.depth + 1),
      parentFingerPrint: this.fingerPrint,
      childIndex: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(index),
      privateKey,
      chainCode
    };
    let derived = $8fc74ca0a6995b3b$export$2e2bcd8739ae039._buildFromBuffers(buffers);
    return new $8fc74ca0a6995b3b$export$2e2bcd8739ae039(derived);
  }
  _deriveFromString(path) {
    if (!$8fc74ca0a6995b3b$export$2e2bcd8739ae039.isValidPath(path)) throw new $824be92afb10ca74$export$b59b0d37c3755b05(path);
    const deriveKeys = (baseKey, indexes2) => {
      return indexes2.reduce((prev, idx) => prev._deriveWithNumber(idx), baseKey);
    };
    let indexes = $850698057fd6f95c$export$2e2bcd8739ae039.getDerivationIndexes(path);
    return deriveKeys(this, indexes);
  }
  static _buildFromSeed(seed, network = $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork) {
    if ($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(seed)) seed = Buffer$1.from(seed, "hex");
    if (!Buffer$1.isBuffer(seed)) throw new $824be92afb10ca74$export$c8ad90567a3adc29(seed);
    if (seed.length < this.MINIMUM_ENTROPY_BITS * this.BITS_TO_BYTES) throw new $824be92afb10ca74$export$18f1c215e936cdfa(seed);
    if (seed.length > this.MAXIMUM_ENTROPY_BITS * this.BITS_TO_BYTES) throw new $824be92afb10ca74$export$136e7f0d62b8ef6f(seed);
    let hash = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha512hmac(seed, Buffer$1.from("Bitcoin seed"));
    let buffers = {
      version: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(($a89918d61ea4dca0$export$f09b1917886389c3.get(network) || $a89918d61ea4dca0$export$f09b1917886389c3.defaultNetwork).xprivkey),
      depth: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsSingleByteBuffer(0),
      parentFingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(0),
      childIndex: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(0),
      privateKey: hash.subarray(0, 32),
      chainCode: hash.subarray(32, 64)
    };
    return this._buildFromBuffers(buffers);
  }
  static _buildFromObject(arg) {
    return {
      network: $a89918d61ea4dca0$export$f09b1917886389c3.get(arg.network),
      depth: arg.depth,
      fingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(arg.fingerPrint),
      parentFingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(arg.parentFingerPrint),
      childIndex: arg.childIndex,
      chainCode: Buffer$1.from(arg.chainCode, "hex"),
      xprivkey: arg.xprivkey,
      checksum: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(arg.checksum),
      privateKey: $9e7155c0d97105d3$export$2e2bcd8739ae039.fromString(arg.privateKey, arg.network)
    };
  }
  static _buildFromMinimalObject(arg) {
    let buffers = {
      version: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer($a89918d61ea4dca0$export$f09b1917886389c3.get(arg.network).xprivkey),
      depth: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsSingleByteBuffer(arg.depth),
      parentFingerPrint: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(arg.parentFingerPrint),
      childIndex: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerAsBuffer(arg.childIndex),
      chainCode: Buffer$1.from(arg.chainCode, "hex"),
      privateKey: Buffer$1.from(arg.privateKey, "hex")
    };
    return this._buildFromBuffers(buffers);
  }
  static _buildFromSerialized(xprivkey) {
    let decoded = $7daa49d6586b1e1a$export$2e2bcd8739ae039.decode(xprivkey);
    let buffers = {
      version: decoded.subarray($850698057fd6f95c$export$2e2bcd8739ae039.VersionStart, $850698057fd6f95c$export$2e2bcd8739ae039.VersionEnd),
      depth: decoded.subarray($850698057fd6f95c$export$2e2bcd8739ae039.DepthStart, $850698057fd6f95c$export$2e2bcd8739ae039.DepthEnd),
      parentFingerPrint: decoded.subarray($850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintStart, $850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintEnd),
      childIndex: decoded.subarray($850698057fd6f95c$export$2e2bcd8739ae039.ChildIndexStart, $850698057fd6f95c$export$2e2bcd8739ae039.ChildIndexEnd),
      chainCode: decoded.subarray($850698057fd6f95c$export$2e2bcd8739ae039.ChainCodeStart, $850698057fd6f95c$export$2e2bcd8739ae039.ChainCodeEnd),
      privateKey: decoded.subarray(this.PrivateKeyStart, this.PrivateKeyEnd),
      checksum: decoded.subarray(this.ChecksumStart, this.ChecksumEnd)
    };
    return this._buildFromBuffers(buffers);
  }
  /**
  * Receives a object with buffers in all the properties and populates the
  * internal structure
  */
  static _buildFromBuffers(arg) {
    $8fc74ca0a6995b3b$export$2e2bcd8739ae039._validateBufferArguments(arg);
    let sequence = [
      arg.version,
      arg.depth,
      arg.parentFingerPrint,
      arg.childIndex,
      arg.chainCode,
      Buffer$1.alloc(1),
      arg.privateKey
    ];
    let concat = Buffer$1.concat(sequence);
    if (!arg.checksum?.length) arg.checksum = $7daa49d6586b1e1a$export$2e2bcd8739ae039.checksum(concat);
    else if (arg.checksum.toString() !== $7daa49d6586b1e1a$export$2e2bcd8739ae039.checksum(concat).toString()) throw new $824be92afb10ca74$export$11fc854522c14d8d(concat);
    let network = $a89918d61ea4dca0$export$f09b1917886389c3.get($9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(arg.version));
    let privateKey = $9e7155c0d97105d3$export$2e2bcd8739ae039.from($5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(arg.privateKey), network);
    let publicKey = privateKey.toPublicKey();
    return {
      xprivkey: $7daa49d6586b1e1a$export$2e2bcd8739ae039.encode(concat),
      network,
      depth: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromSingleByteBuffer(arg.depth),
      privateKey,
      publicKey,
      fingerPrint: $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256ripemd160(publicKey.toBuffer()).subarray(0, $850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintSize),
      chainCode: arg.chainCode,
      childIndex: $9f918c10ad4fef51$export$2e2bcd8739ae039.integerFromBuffer(arg.childIndex),
      parentFingerPrint: arg.parentFingerPrint,
      checksum: arg.checksum
    };
  }
  static _validateBufferArguments(arg) {
    const checkBuffer = (name, size) => {
      let buff = arg[name];
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buff), name + " argument is not a buffer");
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(buff.length === size, name + " has not the expected size: found " + buff.length + ", expected " + size);
    };
    checkBuffer("version", $850698057fd6f95c$export$2e2bcd8739ae039.VersionSize);
    checkBuffer("depth", $850698057fd6f95c$export$2e2bcd8739ae039.DepthSize);
    checkBuffer("parentFingerPrint", $850698057fd6f95c$export$2e2bcd8739ae039.ParentFingerPrintSize);
    checkBuffer("childIndex", $850698057fd6f95c$export$2e2bcd8739ae039.ChildIndexSize);
    checkBuffer("chainCode", $850698057fd6f95c$export$2e2bcd8739ae039.ChainCodeSize);
    checkBuffer("privateKey", this.PrivateKeySize);
    if (arg.checksum?.length) checkBuffer("checksum", $850698057fd6f95c$export$2e2bcd8739ae039.CheckSumSize);
  }
  static _generateRandomly(network) {
    return this._buildFromSeed($9f918c10ad4fef51$export$2e2bcd8739ae039.getRandomBuffer(64), network);
  }
  /**
  * Will return the corresponding hd public key
  *
  * @returns An extended public key generated from the hd private key
  */
  getHDPublicKey() {
    if (!this._hdPublicKey) this._hdPublicKey = new $ef69ee312dbfbba6$export$2e2bcd8739ae039(this);
    return this._hdPublicKey;
  }
  /**
  * Returns the console representation of this extended private key.
  */
  inspect() {
    return `<HDPrivateKey: ${this}>`;
  }
}
class $62ed62398e988143$export$2e2bcd8739ae039 {
  static {
    this.MAGIC_BYTES = Buffer$1.from("Bitcoin Signed Message:\n");
  }
  constructor(message) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(message), "First argument should be a string");
    this.message = message;
  }
  /**
  * Will sign a message with a given private key.
  *
  * @param privateKey An instance of PrivateKey
  * @returns A base64 encoded compact signature
  */
  sign(privateKey) {
    let signature = this._sign(privateKey);
    return signature.toCompact().toString("base64");
  }
  /**
  * Will return a boolean of the signature is valid for a given nexa address.
  * If it isn't valid, the specific reason is accessible via the "error" member.
  *
  * @param nexaAddress A nexa address
  * @param signatureString A base64 encoded compact signature
  */
  verify(nexaAddress, signatureString) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isNil(nexaAddress), "nexaAddress");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(signatureString) && signatureString.length > 0, "signatureString");
    if (isString(nexaAddress)) nexaAddress = $92cd415860c918d9$export$2e2bcd8739ae039.fromString(nexaAddress);
    let signature = $369a157b63fbc3fd$export$2e2bcd8739ae039.fromCompact(Buffer$1.from(signatureString, "base64"));
    let ecdsa = new $1ef65db4b26d2b16$export$2e2bcd8739ae039();
    ecdsa.hashbuf = this._magicHash();
    ecdsa.sig = signature;
    let publicKey = ecdsa.toPublicKey();
    let signatureAddress = $92cd415860c918d9$export$2e2bcd8739ae039.fromPublicKey(publicKey, nexaAddress.network, nexaAddress.type);
    if (nexaAddress.toString() !== signatureAddress.toString()) {
      this.error = "The signature did not match the message digest";
      return false;
    }
    return this._verify(publicKey, signature);
  }
  _sign(privateKey) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(privateKey instanceof $9e7155c0d97105d3$export$2e2bcd8739ae039, "First argument should be an instance of PrivateKey");
    let hash = this._magicHash();
    let ecdsa = new $1ef65db4b26d2b16$export$2e2bcd8739ae039();
    ecdsa.hashbuf = hash;
    ecdsa.privkey = privateKey;
    ecdsa.pubkey = privateKey.toPublicKey();
    ecdsa.signRandomK();
    ecdsa.calcI();
    return ecdsa.sig;
  }
  _magicHash() {
    let prefix1 = $35852622c8c617e8$export$2e2bcd8739ae039.varintBufNum($62ed62398e988143$export$2e2bcd8739ae039.MAGIC_BYTES.length);
    let messageBuffer = Buffer$1.from(this.message);
    let prefix2 = $35852622c8c617e8$export$2e2bcd8739ae039.varintBufNum(messageBuffer.length);
    let buf = Buffer$1.concat([
      prefix1,
      $62ed62398e988143$export$2e2bcd8739ae039.MAGIC_BYTES,
      prefix2,
      messageBuffer
    ]);
    let hash = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf);
    return hash;
  }
  _verify(publicKey, signature) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(publicKey instanceof $246eb589bb078d6d$export$2e2bcd8739ae039, "First argument should be an instance of PublicKey");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(signature instanceof $369a157b63fbc3fd$export$2e2bcd8739ae039, "Second argument should be an instance of Signature");
    let hash = this._magicHash();
    let verified = $1ef65db4b26d2b16$export$2e2bcd8739ae039.verify(hash, signature, publicKey);
    if (!verified) this.error = "The signature was invalid";
    return verified;
  }
  /**
  * Instantiate a message from a message string
  *
  * @param str A string of the message
  * @returns A new instance of a Message
  */
  static fromString(str) {
    return new $62ed62398e988143$export$2e2bcd8739ae039(str);
  }
  /**
  * Instantiate a message from JSON
  *
  * @param json An JSON string or Object with keys: message
  * @returns A new instance of a Message
  */
  static fromJSON(json) {
    if ($c337f7a9455509cf$export$2e2bcd8739ae039.isValidJSON(json)) json = JSON.parse(json);
    return new $62ed62398e988143$export$2e2bcd8739ae039(json.message);
  }
  /**
  * @returns A plain object with the message information
  */
  toObject() {
    return {
      message: this.message
    };
  }
  /**
  * @returns A JSON representation as string of the message information
  */
  toJSON() {
    return JSON.stringify(this.toObject());
  }
  /**
  * Will return a the string representation of the message
  */
  toString() {
    return this.message;
  }
  /**
  * Will return a string formatted for the console
  */
  inspect() {
    return `<Message: ${this}>`;
  }
}
var $a0743653d736276e$export$8da1cb8322810fc2 = /* @__PURE__ */ (function(GroupIdType) {
  GroupIdType[GroupIdType["LEGACY"] = 88888888] = "LEGACY";
  GroupIdType[GroupIdType["NRC1"] = 88888890] = "NRC1";
  GroupIdType[GroupIdType["NRC2"] = 88888891] = "NRC2";
  GroupIdType[GroupIdType["NRC3"] = 88888892] = "NRC3";
  return GroupIdType;
})({});
const $a0743653d736276e$var$AUTH_FLAGS = {
  /** Is this a controller utxo (forces negative number in amount) */
  AUTHORITY: 1n << 63n,
  /** Can mint tokens */
  MINT: 1n << 62n,
  /** Can melt tokens */
  MELT: 1n << 61n,
  /** Can create authorities */
  BATON: 1n << 60n,
  /** Can change the redeem script */
  RESCRIPT: 1n << 59n,
  /** Can create subgroups */
  SUBGROUP: 1n << 58n,
  NONE: 0n,
  ALL_FLAG_BITS: 0xffffn << 64n - 16n
};
const $a0743653d736276e$var$ACTIVE_FLAG_BITS = $a0743653d736276e$var$AUTH_FLAGS.AUTHORITY | $a0743653d736276e$var$AUTH_FLAGS.MINT | $a0743653d736276e$var$AUTH_FLAGS.MELT | $a0743653d736276e$var$AUTH_FLAGS.BATON | $a0743653d736276e$var$AUTH_FLAGS.RESCRIPT | $a0743653d736276e$var$AUTH_FLAGS.SUBGROUP;
class $a0743653d736276e$export$2e2bcd8739ae039 {
  static {
    this.PARENT_GROUP_ID_SIZE = 32;
  }
  static {
    this.authFlags = {
      ...$a0743653d736276e$var$AUTH_FLAGS,
      ACTIVE_FLAG_BITS: (
        /** Has all permissions */
        $a0743653d736276e$var$ACTIVE_FLAG_BITS
      ),
      RESERVED_FLAG_BITS: $a0743653d736276e$var$ACTIVE_FLAG_BITS & ~$a0743653d736276e$var$AUTH_FLAGS.ALL_FLAG_BITS
    };
  }
  /**
  * Calculate a group ID based on the provided inputs. Pass 'null' to opReturnScript if there is not
  * going to be an OP_RETURN output in the transaction.
  *
  * @param outpoint The input outpoint hash hex or buffer
  * @param opReturnScript opReturn output script
  * @param authFlag group authority flag (use {@link GroupToken.authFlags})
  * @param idFlag group id flag
  * 
  * @returns Object with group id hash buffer and the nonce bigint
  */
  static findGroupId(outpoint, opReturnScript, authFlag, idFlag = 0) {
    let hash;
    let groupFlags = 0;
    let nonce = 0n;
    if (isString(outpoint)) outpoint = Buffer$1.from(outpoint, "hex").reverse();
    if (opReturnScript instanceof $90f45db77a786f2b$export$2e2bcd8739ae039) opReturnScript = opReturnScript.toBuffer();
    do {
      let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
      nonce += 1n;
      nonce = nonce & ~this.authFlags.ALL_FLAG_BITS | authFlag;
      writer.write(outpoint);
      if (opReturnScript != null) writer.writeVarLengthBuf(opReturnScript);
      writer.writeUInt64LEBN($5aa97aebe18a7924$export$2e2bcd8739ae039.fromBigInt(nonce));
      hash = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(writer.toBuffer());
      groupFlags = hash[30] << 8 | hash[31];
    } while (groupFlags != idFlag);
    return {
      hashBuffer: hash,
      nonce
    };
  }
  static _getGroupAddressBuffer(group) {
    if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(group)) return group;
    if ($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(group)) return Buffer$1.from(group, "hex");
    let groupAddress = new $92cd415860c918d9$export$2e2bcd8739ae039(group);
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(groupAddress.isGroupIdentifierAddress(), "Invalid group address");
    return groupAddress.data;
  }
  /**
  * Translates a group and additional data into a subgroup identifier
  *
  * @param group the group/token address or data buffer
  * @param data the additional data
  * 
  * @returns the subgroup id buffer
  */
  static generateSubgroupId(group, data) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(group), "group is missing");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(data), "data is missing");
    group = this._getGroupAddressBuffer(group);
    if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(data)) return Buffer$1.concat([
      group,
      data
    ]);
    if (isNumber$1(data)) {
      let bn = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromNumber(data).toBuffer({
        size: 8,
        endian: "little"
      });
      return Buffer$1.concat([
        group,
        bn
      ]);
    }
    if ($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(data)) return Buffer$1.concat([
      group,
      Buffer$1.from(data, "hex")
    ]);
    return Buffer$1.concat([
      group,
      Buffer$1.from(data)
    ]);
  }
  /**
  * Extract the parent group from the provided subgroup.
  * 
  * @remarks
  * If the input is a group but not subgroup, the group itself return.
  * 
  * @param subgroup the subgroup address or data buffer
  * @returns the GroupId buffer
  */
  static getParentGroupId(subgroup) {
    let buf = this._getGroupAddressBuffer(subgroup);
    if (buf.length < this.PARENT_GROUP_ID_SIZE) throw new Error("Invalid subgroup");
    return Buffer$1.from(buf.subarray(0, 32));
  }
  /**
  * Get group amount buffer from BigInt to include in output script
  *
  * @param amount
  */
  static getAmountBuffer(amount) {
    let bw = new $35852622c8c617e8$export$2e2bcd8739ae039();
    if (amount < 0n) {
      let bn = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBigInt(BigInt.asUintN(64, amount));
      bw.writeUInt64LEBN(bn);
    } else if (amount < 0x10000n) bw.writeUInt16LE(Number(amount));
    else if (amount < 0x100000000n) bw.writeUInt32LE(Number(amount));
    else {
      let bn = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBigInt(amount);
      bw.writeUInt64LEBN(bn);
    }
    return bw.toBuffer();
  }
  /**
  * Get group amount value from Buffer
  *
  * @param amountBuf the amount buffer
  * @param unsigned return value as unsigned bigint, default to false
  */
  static getAmountValue(amountBuf, unsigned = false) {
    let amount = $5aa97aebe18a7924$export$2e2bcd8739ae039.fromBuffer(amountBuf, {
      endian: "little"
    }).toBigInt();
    return unsigned ? amount : BigInt.asIntN(64, amount);
  }
  /**
  * @param authFlag the utxo group quantity/authority
  * @returns the nonce
  */
  static getNonce(authFlag) {
    authFlag = BigInt.asUintN(64, authFlag);
    return authFlag & ~this.authFlags.ALL_FLAG_BITS;
  }
  /**
  * Check if the group id has the flag
  * 
  * @param groupId the group id address or data buffer
  * @param groupIdFlag the group id flag
  * @returns true if this group id has the flag
  */
  static hasIdFlag(groupId, groupIdFlag) {
    groupId = this._getGroupAddressBuffer(groupId);
    return groupId.length >= this.PARENT_GROUP_ID_SIZE ? ((groupId[30] << 8 | groupId[31]) & groupIdFlag) == groupIdFlag : false;
  }
  /**
  * Check if this authority and flag fit to this group creation
  * 
  * @param groupId the group id address or data buffer
  * @param authFlag the output group quantity/authority
  * @param groupIdFlag optional. the group id flag
  * @returns true if this is group creation data
  */
  static isGroupCreation(groupId, authFlag, groupIdFlag = 0) {
    groupId = this._getGroupAddressBuffer(groupId);
    authFlag = BigInt.asUintN(64, authFlag);
    let hasNonce = this.getNonce(authFlag) != 0n;
    let isAuth = this.isAuthority(authFlag);
    let hasFlag = this.hasIdFlag(groupId, groupIdFlag);
    return isAuth && hasNonce && hasFlag;
  }
  /**
  * Check if this group is is subgroup
  * 
  * @param groupId the group id address or data buffer
  * @returns true if this group id is subgroup
  */
  static isSubgroup(groupId) {
    groupId = this._getGroupAddressBuffer(groupId);
    return groupId.length > this.PARENT_GROUP_ID_SIZE;
  }
  /**
  * Check if the group quantity/authority is Authority flag
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this is authority flag
  */
  static isAuthority(authFlag) {
    return (authFlag & this.authFlags.AUTHORITY) == this.authFlags.AUTHORITY;
  }
  /**
  * Check if the group quantity/authority allows minting
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this flag allows minting.
  */
  static allowsMint(authFlag) {
    return (authFlag & ($a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY | $a0743653d736276e$export$2e2bcd8739ae039.authFlags.MINT)) == ($a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY | $a0743653d736276e$export$2e2bcd8739ae039.authFlags.MINT);
  }
  /**
  * Check if the group quantity/authority allows melting
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this flag allows melting.
  */
  static allowsMelt(authFlag) {
    return (authFlag & ($a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY | $a0743653d736276e$export$2e2bcd8739ae039.authFlags.MELT)) == ($a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY | $a0743653d736276e$export$2e2bcd8739ae039.authFlags.MELT);
  }
  /**
  * Check if the group quantity/authority allows creation of new authorities
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this flag allows creation of authorities.
  */
  static allowsRenew(authFlag) {
    return (authFlag & ($a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY | $a0743653d736276e$export$2e2bcd8739ae039.authFlags.BATON)) == ($a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY | $a0743653d736276e$export$2e2bcd8739ae039.authFlags.BATON);
  }
  /**
  * Check if the group quantity/authority allows rescript
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this flag allows rescripting.
  */
  static allowsRescript(authFlag) {
    return (authFlag & ($a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY | $a0743653d736276e$export$2e2bcd8739ae039.authFlags.RESCRIPT)) == ($a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY | $a0743653d736276e$export$2e2bcd8739ae039.authFlags.RESCRIPT);
  }
  /**
  * Check if the group quantity/authority allows creation of subgroups
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this flag allows subgroups
  */
  static allowsSubgroup(authFlag) {
    return (authFlag & ($a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY | $a0743653d736276e$export$2e2bcd8739ae039.authFlags.SUBGROUP)) == ($a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY | $a0743653d736276e$export$2e2bcd8739ae039.authFlags.SUBGROUP);
  }
  /**
  * Verify token description document json signature
  *
  * @param jsonDoc the json TDD as string
  * @param address nexa address that signed the doc
  * @param signature the signature string. optional - if empty, extract from jsonDoc
  * 
  * @returns true if signature match
  */
  static verifyJsonDoc(jsonDoc, address, signature) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isEmpty(jsonDoc), "jsonDoc is missing");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isEmpty(address), "group is missing");
    let json = jsonDoc.substring(jsonDoc.indexOf("{"), jsonDoc.lastIndexOf("}") + 1);
    if (isUndefined(signature) || isEmpty(signature)) signature = JSON.parse(jsonDoc)[1];
    let msg = new $62ed62398e988143$export$2e2bcd8739ae039(json);
    return msg.verify(address, signature);
  }
  /**
  * Sign token description document json
  *
  * @param jsonDoc the json TDD as string
  * @param privKey private key to sign on the doc
  * 
  * @returns the signature string
  */
  static signJsonDoc(jsonDoc, privKey) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isEmpty(jsonDoc), "jsonDoc is missing");
    let json = jsonDoc.substring(jsonDoc.indexOf("{"), jsonDoc.lastIndexOf("}") + 1);
    let msg = new $62ed62398e988143$export$2e2bcd8739ae039(json);
    return msg.sign(privKey);
  }
}
class $fea109eb8128bf4c$export$2e2bcd8739ae039 {
  /**
  * @param to destination address or public key
  * @param groupId group id buffer or group address or hex id - only if its token output script
  * @param groupAmount optional. quantity amount buffer or bigint - only if its token output script
  * 
  * @returns a new pay to public key / script template output for the given address or public key
  */
  static buildScriptTemplateOut(to, groupId, groupAmount) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(to), "to", "must provide an argument");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(to instanceof $246eb589bb078d6d$export$2e2bcd8739ae039 || to instanceof $92cd415860c918d9$export$2e2bcd8739ae039 || isString(to), "to", "must be address or pubkey");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isNil(groupId) && isNil(groupAmount) || !isNil(groupId) && !isNil(groupAmount), "group data", "both must present or both not present");
    to = this.parseAddress(to);
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(to.isPayToScriptTemplate(), "Invalid destination address (not a script template)");
    if (isString(groupId)) {
      if ($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(groupId)) groupId = Buffer$1.from(groupId, "hex");
      else {
        let groupIdAddr = $92cd415860c918d9$export$2e2bcd8739ae039.fromString(groupId);
        $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(groupIdAddr.isGroupIdentifierAddress(), "Invalid group id address (not a group)");
        groupId = groupIdAddr.data;
      }
    } else if (groupId instanceof $92cd415860c918d9$export$2e2bcd8739ae039) {
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(groupId.isGroupIdentifierAddress(), "Invalid group id address (not a group)");
      groupId = groupId.data;
    }
    if (typeof groupAmount === "bigint") groupAmount = $a0743653d736276e$export$2e2bcd8739ae039.getAmountBuffer(groupAmount);
    let bfr = new $12fea2c2eb591556$export$2e2bcd8739ae039(to.data).readVarLengthBuffer();
    let s = $90f45db77a786f2b$export$2e2bcd8739ae039.fromBuffer(bfr);
    if (!isNil(groupId) && !isNil(groupAmount)) {
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(groupId), "groupId");
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(groupAmount), "groupAmount");
      s.chunks = s.chunks.slice(1);
      s.prepend(groupAmount).prepend(groupId);
    }
    return s;
  }
  /**
  * @param data the data to embed in the output
  * @param encoding the type of encoding of the string
  * 
  * @returns a new OP_RETURN script with data
  */
  static buildDataOut(data, encoding) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isUndefined(data) || isString(data) || $9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(data) || data instanceof $90f45db77a786f2b$export$2e2bcd8739ae039, "data");
    if (isString(data)) data = Buffer$1.from(data, encoding);
    let s = $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add($92c0719d4ab9ac45$export$393941f88fd16991.OP_RETURN);
    if (!isUndefined(data)) s.add(data);
    return s;
  }
  /**
  * @param address the pay to address
  * @param groupId optional. only for p2st addresses
  * @param groupAmount optional. only for p2st addresses
  * 
  * @return an output script built from the address
  */
  static buildOutFromAddress(address, groupId, groupAmount) {
    if (isString(address)) address = $92cd415860c918d9$export$2e2bcd8739ae039.fromString(address);
    if (address.isPayToPublicKeyHash()) return this.buildPublicKeyHashOut(address);
    else if (address.isPayToScriptTemplate()) return this.buildScriptTemplateOut(address, groupId, groupAmount);
    throw new Error(`Invalid address type: ${address.type}`);
  }
  /**
  * Builds a scriptSig (a script for an input) that signs a script template
  * output script.
  *
  * @param template the template script or OP_1 for well-known
  * @param constraint the constraint script or OP_FALSE
  * @param satisfier the satisfier script or buffer
  */
  static buildScriptTemplateIn(template, constraint, satisfier) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(template instanceof $90f45db77a786f2b$export$2e2bcd8739ae039 || template === $92c0719d4ab9ac45$export$393941f88fd16991.OP_1, "template");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(constraint instanceof $90f45db77a786f2b$export$2e2bcd8739ae039 || constraint === $92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE, "constraint");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(satisfier instanceof $90f45db77a786f2b$export$2e2bcd8739ae039 || $9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(satisfier), "satisfier");
    let script = $90f45db77a786f2b$export$2e2bcd8739ae039.empty();
    if (template instanceof $90f45db77a786f2b$export$2e2bcd8739ae039) script.add(template.toBuffer());
    if (constraint instanceof $90f45db77a786f2b$export$2e2bcd8739ae039) script.add(constraint.toBuffer());
    if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(satisfier)) satisfier = $90f45db77a786f2b$export$2e2bcd8739ae039.fromBuffer(satisfier);
    script.add(satisfier);
    return script;
  }
  static parseAddress(address, type) {
    if (isString(address)) return $92cd415860c918d9$export$2e2bcd8739ae039.fromString(address);
    else if (address instanceof $246eb589bb078d6d$export$2e2bcd8739ae039) return $92cd415860c918d9$export$2e2bcd8739ae039.fromPublicKey(address, address.network, type);
    return address;
  }
  /**
  * @param to - destination address or public key
  * 
  * @returns a new pay to public key hash output for the given
  * address or public key
  */
  static buildPublicKeyHashOut(to) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(to), "to", "must provide an argument");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(to instanceof $246eb589bb078d6d$export$2e2bcd8739ae039 || to instanceof $92cd415860c918d9$export$2e2bcd8739ae039 || isString(to), "to", "must be address or pubkey");
    to = this.parseAddress(to, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash);
    return $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add($92c0719d4ab9ac45$export$393941f88fd16991.OP_DUP).add($92c0719d4ab9ac45$export$393941f88fd16991.OP_HASH160).add(to.data).add($92c0719d4ab9ac45$export$393941f88fd16991.OP_EQUALVERIFY).add($92c0719d4ab9ac45$export$393941f88fd16991.OP_CHECKSIG);
  }
  /**
  * Builds a scriptSig (a script for an input) that signs a public key hash
  * output script. (SIGHASH_ALL only)
  *
  * @param publicKey
  * @param signature a Signature object, or the signature in DER canonical encoding
  */
  static buildPublicKeyHashIn(publicKey, signature) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(publicKey instanceof $246eb589bb078d6d$export$2e2bcd8739ae039, "publicKey");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(signature instanceof $369a157b63fbc3fd$export$2e2bcd8739ae039 || $9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(signature), "signature");
    if (signature instanceof $369a157b63fbc3fd$export$2e2bcd8739ae039) signature = signature.toBuffer();
    let script = $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add(signature).add(publicKey.toBuffer());
    return script;
  }
  /**
  * Build OP_RETURN output script for Legacy Token Description
  *
  * @param ticker the ticker as utf8.
  * @param name the ticker as utf8.
  * @param docUrl optional. the description document url
  * @param docHash optional. the document hash hex.
  * @param decimals optional. the decimals for the token amount.
  * 
  * @throws Error if docUrl provided and is invalid
  * 
  * @returns the output OP_RETURN script
  */
  static buildTokenDescriptionLegacy(ticker, name, docUrl, docHash, decimals) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(ticker) && inRange(ticker.length, 1, 9), "Ticker must be between 1-8 chars");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(name) && !isEmpty(name), "Name is missing");
    let s = $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add($92c0719d4ab9ac45$export$393941f88fd16991.OP_RETURN).add($5aa97aebe18a7924$export$2e2bcd8739ae039.fromNumber($a0743653d736276e$export$8da1cb8322810fc2.LEGACY).toScriptNumBuffer()).add(Buffer$1.from(ticker)).add(Buffer$1.from(name));
    if (docUrl && docUrl.length > 0) {
      new URL(docUrl);
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(docHash) && !isEmpty(docHash), "You must include document hash if you set document url");
      s.add(Buffer$1.from(docUrl)).add(Buffer$1.from(docHash, "hex").reverse());
    } else s.add($92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE).add($92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE);
    if (isNumber$1(decimals)) {
      $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(inRange(decimals, 0, 19), "decimals must be between 0 and 18");
      s.add(decimals <= 16 ? $92c0719d4ab9ac45$export$2e2bcd8739ae039.smallInt(decimals) : $5aa97aebe18a7924$export$2e2bcd8739ae039.fromNumber(decimals).toScriptNumBuffer());
    }
    return s;
  }
  /**
  * Build OP_RETURN output script for NRC1 Token Description
  *
  * @param ticker the ticker as utf8.
  * @param name the ticker as utf8.
  * @param zipURL the zip file url.
  * @param zipHash the zip file hash hex.
  * @param decimals the decimals for the token amount.
  * 
  * @throws Error if zipURL invalid
  * 
  * @returns the output OP_RETURN script
  */
  static buildTokenDescription(ticker, name, zipURL, zipHash, decimals) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(ticker) && inRange(ticker.length, 2, 9), "Ticker must be 2-8 chars");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(name) && inRange(name.length, 2, 26), "Name must be 2-25 chars");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(zipURL) && !isEmpty(zipURL), "Zip URL is missing");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(zipHash) && !isEmpty(zipHash), "Zip hash is missing");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isNumber$1(decimals) && inRange(decimals, 0, 19), "Decimals must be a number 0-18");
    new URL(zipURL);
    return $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add($92c0719d4ab9ac45$export$393941f88fd16991.OP_RETURN).add($5aa97aebe18a7924$export$2e2bcd8739ae039.fromNumber($a0743653d736276e$export$8da1cb8322810fc2.NRC1).toScriptNumBuffer()).add(Buffer$1.from(ticker)).add(Buffer$1.from(name)).add(Buffer$1.from(zipURL)).add(Buffer$1.from(zipHash, "hex").reverse()).add(decimals <= 16 ? $92c0719d4ab9ac45$export$2e2bcd8739ae039.smallInt(decimals) : $5aa97aebe18a7924$export$2e2bcd8739ae039.fromNumber(decimals).toScriptNumBuffer());
  }
  /**
  * Build OP_RETURN output script for an NFT Collection Description (NRC2)
  *
  * @param ticker the ticker as utf8.
  * @param name the ticker as utf8.
  * @param zipURL the zip file url.
  * @param zipHash the zip file hash hex.
  * 
  * @throws Error if zipURL invalid 
  * 
  * @returns the output OP_RETURN script
  */
  static buildNFTCollectionDescription(ticker, name, zipURL, zipHash) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(ticker) && inRange(ticker.length, 2, 9), "Ticker must be 2-8 chars");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(name) && inRange(name.length, 2, 26), "Name must be 2-25 chars");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(zipURL) && !isEmpty(zipURL), "Zip URL is missing");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(zipHash) && !isEmpty(zipHash), "Zip hash is missing");
    new URL(zipURL);
    return $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add($92c0719d4ab9ac45$export$393941f88fd16991.OP_RETURN).add($5aa97aebe18a7924$export$2e2bcd8739ae039.fromNumber($a0743653d736276e$export$8da1cb8322810fc2.NRC2).toScriptNumBuffer()).add(Buffer$1.from(ticker)).add(Buffer$1.from(name)).add(Buffer$1.from(zipURL)).add(Buffer$1.from(zipHash, "hex").reverse()).add($92c0719d4ab9ac45$export$2e2bcd8739ae039.smallInt(0));
  }
  /**
  * Build OP_RETURN output script for an NFT that belongs to an NFT Collection (NRC3)
  *
  * @param zipURL the zip file url.
  * @param zipHash the zip file hash hex.
  * 
  * @throws Error if zipURL invalid 
  * 
  * @returns the output OP_RETURN script
  */
  static buildNFTDescription(zipURL, zipHash) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(zipURL) && !isEmpty(zipURL), "Zip URL is missing");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(zipHash) && !isEmpty(zipHash), "Zip hash is missing");
    new URL(zipURL);
    return $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add($92c0719d4ab9ac45$export$393941f88fd16991.OP_RETURN).add($5aa97aebe18a7924$export$2e2bcd8739ae039.fromNumber($a0743653d736276e$export$8da1cb8322810fc2.NRC3).toScriptNumBuffer()).add(Buffer$1.from(zipURL)).add(Buffer$1.from(zipHash, "hex").reverse());
  }
}
var $e50a883097cd2090$export$ae38be9ef660d12e = /* @__PURE__ */ (function(InputSighashType) {
  InputSighashType[InputSighashType["ALL"] = 0] = "ALL";
  InputSighashType[InputSighashType["FIRSTN"] = 1] = "FIRSTN";
  InputSighashType[InputSighashType["THISIN"] = 2] = "THISIN";
  InputSighashType[InputSighashType["LAST_VALID"] = 2] = "LAST_VALID";
  return InputSighashType;
})({});
var $e50a883097cd2090$export$cc0d5ed6c4786851 = /* @__PURE__ */ (function(OutputSighashType) {
  OutputSighashType[OutputSighashType["ALL"] = 0] = "ALL";
  OutputSighashType[OutputSighashType["FIRSTN"] = 1] = "FIRSTN";
  OutputSighashType[OutputSighashType["TWO"] = 2] = "TWO";
  OutputSighashType[OutputSighashType["LAST_VALID"] = 2] = "LAST_VALID";
  return OutputSighashType;
})({});
class $e50a883097cd2090$export$2e2bcd8739ae039 {
  static {
    this.MAX_SIZE = 4;
  }
  constructor() {
    this.inType = 0;
    this.outType = 0;
    this.inData = [];
    this.outData = [];
  }
  /**
  * creates a sighash that is the most restrictive -- it signs all inputs and outputs
  */
  static get ALL() {
    return new $e50a883097cd2090$export$2e2bcd8739ae039();
  }
  hasAll() {
    return this.inType == 0 && this.outType == 0;
  }
  isInvalid() {
    return this.inType > 2 || this.outType > 2;
  }
  /** 
  * Anyone can pay signs only the current input, so other entities can add addtl inputs to complete the partial tx
  */
  setAnyoneCanPay() {
    this.inType = 2;
    this.inData = [];
    return this;
  }
  /**
  * Include only the n first inputs in the preimage sighash
  * 
  * @param n The first inputs to include
  */
  setFirstNIn(n) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(n >= 0 && n < 256, "n", "out of range (0-255).");
    this.inType = 1;
    this.inData = [
      n
    ];
    return this;
  }
  /**
  * Include only the n first outputs in the preimage sighash
  * 
  * @param n The first outputs to include
  */
  setFirstNOut(n) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(n >= 0 && n < 256, "n", "out of range (0-255).");
    this.outType = 1;
    this.outData = [
      n
    ];
    return this;
  }
  /**
  * Include specific 2 outputs in the preimage sighash
  * 
  * @param a The 1st output to include
  * @param b The 2nd output to include
  */
  set2Out(a, b) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(a >= 0 && a < 256, "a", "out of range (0-255).");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(b >= 0 && b < 256, "b", "out of range (0-255).");
    this.outType = 2;
    this.outData = [
      a,
      b
    ];
    return this;
  }
  toBuffer() {
    if (this.hasAll()) return Buffer$1.alloc(0);
    let bw = new $35852622c8c617e8$export$2e2bcd8739ae039();
    let sigtype = this.inType << 4 | this.outType;
    bw.writeUInt8(sigtype);
    switch (this.inType) {
      case 1:
        $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.inData.length > 0, "Missing input data");
        bw.writeUInt8(this.inData[0]);
        break;
      case 2:
      case 0:
        break;
      default:
        throw new Error("Malformed sighash type");
    }
    switch (this.outType) {
      case 2:
        $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.outData.length > 1, "Missing output data");
        bw.writeUInt8(this.outData[0]);
        bw.writeUInt8(this.outData[1]);
        break;
      case 1:
        $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.outData.length > 0, "Missing output data");
        bw.writeUInt8(this.outData[0]);
        break;
      case 0:
        break;
      default:
        throw new Error("Malformed sighash type");
    }
    return bw.toBuffer();
  }
  static fromBuffer(buf) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(buf), "buf");
    if (buf.length == 0) return this.ALL;
    let sighash = new $e50a883097cd2090$export$2e2bcd8739ae039();
    let br = new $12fea2c2eb591556$export$2e2bcd8739ae039(buf);
    let type = br.readUInt8();
    sighash.outType = type & 15;
    sighash.inType = type >> 4;
    if (sighash.isInvalid()) throw new Error("Invalid sighash buffer");
    const safeRead = (br2) => {
      if (br2.finished()) throw new Error("Invalid sighash buffer");
      return br2.readUInt8();
    };
    if (sighash.inType == 1) sighash.inData.push(safeRead(br));
    if (sighash.outType == 1) sighash.outData.push(safeRead(br));
    else if (sighash.outType == 2) {
      sighash.outData.push(safeRead(br));
      sighash.outData.push(safeRead(br));
    }
    if (!br.finished()) throw new Error("Invalid sighash buffer");
    return sighash;
  }
  /**
  * Convert to a hex representation of the sighash
  */
  toHex() {
    return this.toBuffer().toString("hex");
  }
  /**
  * Create sighash for hex represantation
  * @see toHex 
  */
  static fromHex(hex) {
    if (typeof hex === "string" && hex.length === 0) return this.ALL;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(hex), "Not a hex string");
    return this.fromBuffer(Buffer$1.from(hex, "hex"));
  }
  /** 
  * Convert to a human readable representation of the sighash
  */
  toString() {
    if (this.hasAll()) return "ALL";
    let ret = "";
    switch (this.inType) {
      case 0:
        ret += "ALL_IN";
        break;
      case 2:
        ret += "THIS_IN";
        break;
      case 1:
        ret += `FIRST_${this.inData[0]}_IN`;
        break;
      default:
        return "INVALID";
    }
    ret += "|";
    switch (this.outType) {
      case 0:
        ret += "ALL_OUT";
        break;
      case 2:
        ret += `${this.outData[0]}_${this.outData[1]}_OUT`;
        break;
      case 1:
        ret += `FIRST_${this.outData[0]}_OUT`;
        break;
      default:
        return "INVALID";
    }
    return ret;
  }
  /**
  * Create sighash from human readable represantation
  * @see toString 
  */
  static fromString(str) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isString(str), "Not a string");
    if (str == "ALL") return this.ALL;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(str.includes("|"), "Not a sighash string");
    let sighash = new $e50a883097cd2090$export$2e2bcd8739ae039();
    let [inStr, outStr] = str.split("|");
    if (inStr == "THIS_IN") sighash.inType = 2;
    else if (inStr != "ALL_IN") {
      let match = inStr.match(/^FIRST_(\d+)_IN$/);
      $e44f707fde477092$export$2e2bcd8739ae039.validateState(!isNil(match), "Not a sighash string");
      sighash.setFirstNIn(parseInt(match[1]));
    }
    if (outStr != "ALL_OUT") {
      let fnMatch = outStr.match(/^FIRST_(\d+)_OUT$/);
      let twMatch = outStr.match(/^(\d+)_(\d+)_OUT$/);
      if (fnMatch) sighash.setFirstNOut(parseInt(fnMatch[1]));
      else if (twMatch) sighash.set2Out(parseInt(twMatch[1]), parseInt(twMatch[2]));
      else throw new Error("Not a sighash string");
    }
    return sighash;
  }
}
class $98955c312257c252$export$2e2bcd8739ae039 {
  constructor(value, scriptPubKey, type = 32768) {
    this.toJSON = this.toObject;
    this.type = type;
    this.value = value;
    this.scriptPubKey = scriptPubKey;
  }
  get value() {
    return this._value;
  }
  set value(sats) {
    sats = BigInt(sats);
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($c337f7a9455509cf$export$2e2bcd8739ae039.isNaturalBigInt(sats), "Output value is not a natural bigint");
    this._value = sats;
  }
  get scriptPubKey() {
    return this._scriptPubKey;
  }
  set scriptPubKey(script) {
    if (!isUndefined(this._scriptPubKey)) this.type = 32768;
    if (script instanceof $90f45db77a786f2b$export$2e2bcd8739ae039) this._scriptPubKey = script;
    else if (isString(script)) this._scriptPubKey = $90f45db77a786f2b$export$2e2bcd8739ae039.fromString(script);
    else throw new TypeError("Invalid argument type: script");
    if (this.type == 32768) this.type = this._scriptPubKey.isPublicKeyTemplateOut() || this._scriptPubKey.isScriptTemplateOut() ? 1 : 0;
  }
  invalidValue() {
    if (this.value > BigInt(Number.MAX_SAFE_INTEGER)) return "transaction txout value greater than max safe integer";
    if (this.value < 0n) return "transaction txout negative";
    return false;
  }
  toObject() {
    return {
      type: this.type,
      value: this.value.toString(),
      scriptPubKey: this.scriptPubKey.toHex()
    };
  }
  static fromObject(data) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(data), "data", "Unrecognized argument for Output");
    return new $98955c312257c252$export$2e2bcd8739ae039(data.value, data.scriptPubKey, data.type);
  }
  inspect() {
    return `<Output (type: ${this.type}) (${this.value.toString()} sats) ${this.scriptPubKey.inspect()}>`;
  }
  static fromBufferReader(br) {
    let type = br.readVarintNum();
    let value = br.readUInt64LEBN();
    let size = br.readVarintNum();
    let scriptBuf = size !== 0 ? br.read(size) : Buffer$1.from([]);
    return new $98955c312257c252$export$2e2bcd8739ae039(value.toBigInt(), $90f45db77a786f2b$export$2e2bcd8739ae039.fromBuffer(scriptBuf), type);
  }
  toBufferWriter(writer) {
    if (!writer) writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    writer.writeUInt8(this.type);
    writer.writeUInt64LEBN($5aa97aebe18a7924$export$2e2bcd8739ae039.fromBigInt(this.value));
    writer.writeVarLengthBuf(this.scriptPubKey.toBuffer());
    return writer;
  }
}
class $9b92277fa5d35484$export$2e2bcd8739ae039 {
  static {
    this.SEQUENCE_FINAL = 4294967295;
  }
  constructor(params) {
    this.toJSON = this.toObject;
    if (params) this._set(params);
  }
  get scriptSig() {
    return this._scriptSig;
  }
  set scriptSig(script) {
    if (script instanceof $90f45db77a786f2b$export$2e2bcd8739ae039) this._scriptSig = script;
    else if (isString(script)) this._scriptSig = $90f45db77a786f2b$export$2e2bcd8739ae039.fromString(script);
    else throw new TypeError("Invalid argument type: script");
  }
  _set(params) {
    this.type = 0;
    if (isNil(params.scriptSig)) throw new TypeError("Need a script to create an input");
    this.scriptSig = params.scriptSig;
    this.outpoint = $9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(params.outpoint) ? params.outpoint : Buffer$1.from(params.outpoint, "hex");
    this.amount = BigInt(params.amount);
    this.sequenceNumber = isUndefined(params.sequenceNumber) ? $9b92277fa5d35484$export$2e2bcd8739ae039.SEQUENCE_FINAL : params.sequenceNumber;
    if (params.output) this.output = params.output instanceof $98955c312257c252$export$2e2bcd8739ae039 ? params.output : $98955c312257c252$export$2e2bcd8739ae039.fromObject(params.output);
  }
  static fromObject(obj) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(obj), "obj");
    return new $9b92277fa5d35484$export$2e2bcd8739ae039(obj);
  }
  toObject() {
    return {
      type: this.type,
      outpoint: this.outpoint.toString("hex"),
      amount: this.amount.toString(),
      sequenceNumber: this.sequenceNumber,
      scriptSig: this.scriptSig.toHex(),
      output: this.output?.toObject()
    };
  }
  static fromBufferReader(br) {
    let input = new $9b92277fa5d35484$export$2e2bcd8739ae039();
    input.type = br.readUInt8();
    input.outpoint = br.readReverse(32);
    input.scriptSig = $90f45db77a786f2b$export$2e2bcd8739ae039.fromBuffer(br.readVarLengthBuffer());
    input.sequenceNumber = br.readUInt32LE();
    input.amount = br.readUInt64LEBN().toBigInt();
    return input;
  }
  toBufferWriter(writer, includeScript = true) {
    if (!writer) writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    writer.writeUInt8(this.type);
    writer.writeReverse(this.outpoint);
    if (includeScript) writer.writeVarLengthBuf(this.scriptSig.toBuffer());
    writer.writeUInt32LE(this.sequenceNumber);
    writer.writeUInt64LEBN($5aa97aebe18a7924$export$2e2bcd8739ae039.fromBigInt(this.amount));
    return writer;
  }
  estimateSize() {
    return this.toBufferWriter().toBuffer().length;
  }
  isFinal() {
    return this.sequenceNumber !== $9b92277fa5d35484$export$2e2bcd8739ae039.SEQUENCE_FINAL;
  }
  clearSignatures() {
    this.scriptSig = $90f45db77a786f2b$export$2e2bcd8739ae039.empty();
    return this;
  }
  getSubscript() {
    throw Error(`Abstract Method Invocation: Input#getSubscript`);
  }
  /**
  * @returns true if the provided private key can sign this input
  */
  canSign(_privateKey) {
    throw Error(`Abstract Method Invocation: Input#canSign`);
  }
  isFullySigned() {
    throw Error(`Abstract Method Invocation: Input#isFullySigned`);
  }
  addSignature(_signature) {
    throw Error(`Abstract Method Invocation: Input#addSignature`);
  }
}
class $5cf2ce125ae8c2d7$export$2e2bcd8739ae039 extends $9b92277fa5d35484$export$2e2bcd8739ae039 {
  static {
    this.SCRIPT_SIZE = 99;
  }
  getSubscript() {
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.output instanceof $98955c312257c252$export$2e2bcd8739ae039, "missing associated output");
    return this.output.scriptPubKey;
  }
  canSign(privateKey) {
    if (!(this.output instanceof $98955c312257c252$export$2e2bcd8739ae039)) return false;
    let pkh = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256ripemd160(privateKey.publicKey.toBuffer());
    return pkh.equals(this.output.scriptPubKey.getPublicKeyHash());
  }
  isFullySigned() {
    return this.scriptSig.isPublicKeyHashIn();
  }
  addSignature(signature) {
    this.scriptSig = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildPublicKeyHashIn(signature.publicKey, signature.signature);
    return this;
  }
  estimateSize() {
    if (this.isFullySigned()) return super.estimateSize();
    return 34 + $5cf2ce125ae8c2d7$export$2e2bcd8739ae039.SCRIPT_SIZE + 4 + 8;
  }
}
class $49712dfa37abdb5b$export$2e2bcd8739ae039 extends $9b92277fa5d35484$export$2e2bcd8739ae039 {
  static {
    this.SCRIPT_SIZE = 100;
  }
  getSubscript() {
    return $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add($92c0719d4ab9ac45$export$393941f88fd16991.OP_FROMALTSTACK).add($92c0719d4ab9ac45$export$393941f88fd16991.OP_CHECKSIGVERIFY);
  }
  canSign(privateKey) {
    if (!(this.output instanceof $98955c312257c252$export$2e2bcd8739ae039)) return false;
    let constraintHash = $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256ripemd160($90f45db77a786f2b$export$2e2bcd8739ae039.empty().add(privateKey.publicKey.toBuffer()).toBuffer());
    return constraintHash.equals(this.output.scriptPubKey.getConstraintHash());
  }
  isFullySigned() {
    return this.scriptSig.isPublicKeyTemplateIn();
  }
  addSignature(signature) {
    let constraint = $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add(signature.publicKey.toBuffer());
    let satisfier = $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add(signature.toTxSatisfier());
    this.scriptSig = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildScriptTemplateIn($92c0719d4ab9ac45$export$393941f88fd16991.OP_1, constraint, satisfier);
    return this;
  }
  estimateSize() {
    if (this.isFullySigned()) return super.estimateSize();
    return 34 + $49712dfa37abdb5b$export$2e2bcd8739ae039.SCRIPT_SIZE + 4 + 8;
  }
}
class $6995bc57838749e2$export$2e2bcd8739ae039 extends $9b92277fa5d35484$export$2e2bcd8739ae039 {
  /**
  * Represents a special kind of input of generic ScriptTemplate kind.
  * 
  * WARNING: this is a general case where the signature is similar to p2pkt and added to scriptSig as push signature data.
  * If you have complex smart contract, consider extending this class (or Input class) and implement the necessary logic,
  * or sign it manually.
  */
  constructor(arg) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(arg?.templateData), "Missing template object");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(arg?.output), "Missing associated utxo");
    let td = arg.templateData;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(td.templateScript instanceof $90f45db77a786f2b$export$2e2bcd8739ae039 || isString(td.templateScript), "Invalid template");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(td.constraintScript instanceof $90f45db77a786f2b$export$2e2bcd8739ae039 || isString(td.constraintScript) || td.constraintScript === $92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE, "Invalid constraint");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isUndefined(td.publicKey) || td.publicKey instanceof $246eb589bb078d6d$export$2e2bcd8739ae039 || isString(td.publicKey), "Invalid pubkey");
    super(arg), this.toJSON = this.toObject;
    this.templateScript = isString(td.templateScript) ? $90f45db77a786f2b$export$2e2bcd8739ae039.fromString(td.templateScript) : td.templateScript;
    this.constraintScript = isString(td.constraintScript) ? $90f45db77a786f2b$export$2e2bcd8739ae039.fromString(td.constraintScript) : td.constraintScript;
    this.publicKey = isString(td.publicKey) ? $246eb589bb078d6d$export$2e2bcd8739ae039.fromString(td.publicKey) : td.publicKey;
    let templateHash = this.output.scriptPubKey.getTemplateHash();
    $e44f707fde477092$export$2e2bcd8739ae039.validateState($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(templateHash) && templateHash.equals($62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256ripemd160(this.templateScript.toBuffer())), "Provided template doesn't match to the provided output");
    let constraintHash = this.output.scriptPubKey.getConstraintHash();
    let isScriptMatch = this.constraintScript instanceof $90f45db77a786f2b$export$2e2bcd8739ae039 && $9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(constraintHash) && constraintHash.equals($62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256ripemd160(this.constraintScript.toBuffer()));
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(constraintHash === this.constraintScript || isScriptMatch, "Provided constraint doesn't match to the provided output");
  }
  toObject() {
    let input = super.toObject();
    return {
      ...input,
      templateData: {
        templateScript: this.templateScript.toHex(),
        constraintScript: this.constraintScript === $92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE ? $92c0719d4ab9ac45$export$393941f88fd16991.OP_FALSE : this.constraintScript.toHex(),
        publicKey: this.publicKey?.toString()
      }
    };
  }
  static fromObject(obj) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(obj), "obj");
    return new $6995bc57838749e2$export$2e2bcd8739ae039(obj);
  }
  getSubscript() {
    return this.templateScript;
  }
  canSign(privateKey) {
    return this.publicKey?.toString() === privateKey.publicKey.toString();
  }
  isFullySigned() {
    return this.scriptSig.isScriptTemplateIn() && this.templateScript.equals($90f45db77a786f2b$export$2e2bcd8739ae039.fromBuffer(this.scriptSig.chunks[0].buf)) && (!(this.constraintScript instanceof $90f45db77a786f2b$export$2e2bcd8739ae039) || this.constraintScript.equals($90f45db77a786f2b$export$2e2bcd8739ae039.fromBuffer(this.scriptSig.chunks[1].buf)));
  }
  addSignature(signature) {
    let satisfier = $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add(signature.toTxSatisfier());
    this.scriptSig = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildScriptTemplateIn(this.templateScript, this.constraintScript, satisfier);
    return this;
  }
  estimateSize() {
    if (this.isFullySigned()) return super.estimateSize();
    let scriptSize = this._estimateScriptSize();
    return 33 + (scriptSize < 253 ? 1 : 3) + scriptSize + 4 + 8;
  }
  _estimateScriptSize() {
    let s = $90f45db77a786f2b$export$2e2bcd8739ae039.empty().add(this.templateScript.toBuffer());
    if (this.constraintScript instanceof $90f45db77a786f2b$export$2e2bcd8739ae039) s.add(this.constraintScript.toBuffer());
    return s.toBuffer().length + 1 + 64;
  }
}
class $926e193f4c554367$export$2e2bcd8739ae039 {
  static {
    this.CURRENT_VERSION = 0;
  }
  static {
    this.FEE_PER_BYTE = 3;
  }
  static {
    this.DUST_AMOUNT = 546;
  }
  static {
    this.MAX_MONEY = 21e6 * 1e8;
  }
  static {
    this.NLOCKTIME_BLOCKHEIGHT_LIMIT = 5e8;
  }
  static {
    this.NLOCKTIME_MAX_VALUE = 4294967295;
  }
  constructor(serializedTx) {
    this.uncheckedSerialize = this.toString;
    this.toJSON = this.toObject;
    this.version = $926e193f4c554367$export$2e2bcd8739ae039.CURRENT_VERSION;
    this.inputs = [];
    this.outputs = [];
    this.nLockTime = 0;
    if (serializedTx) {
      if ($9f918c10ad4fef51$export$2e2bcd8739ae039.isBuffer(serializedTx)) this.fromBuffer(serializedTx);
      else if ($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(serializedTx)) this.fromString(serializedTx);
      else if (isObject$1(serializedTx)) this.fromObject(serializedTx);
      else throw new TypeError("Must provide an object or string to deserialize a transaction");
    }
  }
  get id() {
    let buf = new $35852622c8c617e8$export$2e2bcd8739ae039().write(this._getTxIdem()).write(this._getTxSatisfier()).toBuffer();
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf).reverse().toString("hex");
  }
  get idem() {
    return this._getTxIdem().reverse().toString("hex");
  }
  get outputAmount() {
    return this.outputs.reduce((total, output) => total + output.value, 0n);
  }
  get inputAmount() {
    return this.inputs.reduce((total, input) => total + input.amount, 0n);
  }
  _getTxIdem() {
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(this._toIdemBuffer());
  }
  _getTxSatisfier() {
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(this._toSatisfierBuffer());
  }
  /**
  * Create a 'shallow' copy of the transaction, by serializing and deserializing.
  * it dropping any additional information that inputs and outputs may have hold
  *
  * @param transaction
  */
  static shallowCopy(transaction) {
    return new $926e193f4c554367$export$2e2bcd8739ae039(transaction.toBuffer());
  }
  /**
  * Analogous to nexad's IsCoinBase function in transaction.h
  */
  isCoinbase() {
    return this.inputs.length === 0;
  }
  /**
  * Retrieve a possible error that could appear when trying to serialize and
  * broadcast this transaction.
  *
  * @param opts allows to skip certain tests.
  */
  getSerializationError(opts) {
    if (this._invalidAmount()) return new Error("Output satoshis are invalid");
    if (this.outputs.length > 256) return new Error("Too many outputs (> 256)");
    if (this.inputs.length > 256) return new Error("Too many inputs (> 256)");
    let unspent = this.getUnspentValue();
    let unspentError;
    if (unspent < 0) {
      if (!opts?.disableMoreOutputThanInput) unspentError = new Error("Invalid outputs amount sum");
    } else unspentError = this._hasFeeError(unspent);
    return unspentError || this._hasDustOutputs(opts) || this._isMissingSignatures(opts);
  }
  _invalidAmount() {
    return this.outputs.some((out) => out.invalidValue());
  }
  _hasDustOutputs(opts) {
    if (opts?.disableDustOutputs) return;
    let hasDust = this.outputs.some((output) => output.value < $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT && !output.scriptPubKey.isDataOut());
    return hasDust ? new Error("Dust amount detected in one output") : void 0;
  }
  _hasFeeError(unspent) {
    if (!isUndefined(this._fee) && BigInt(this._fee) !== unspent) return new Error(`Unspent value is ${unspent} but specified fee is ${this._fee}`);
  }
  _estimateFee() {
    let estimatedSize = this._estimateSize();
    let available = this.getUnspentValue();
    let feeRate = this._feePerByte || $926e193f4c554367$export$2e2bcd8739ae039.FEE_PER_BYTE;
    const calcFee = (size) => {
      return size * feeRate;
    };
    let feeWithChange = Math.ceil(calcFee(estimatedSize) + calcFee(this._estimateSizeOfChangeOutput()));
    if (!this._changeScript || available <= feeWithChange || available - BigInt(feeWithChange) < $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT) return Number(available);
    return feeWithChange;
  }
  _estimateSizeOfChangeOutput() {
    if (!this._changeScript) return 0;
    let scriptLen = this._changeScript.toBuffer().length;
    return 9 + $35852622c8c617e8$export$2e2bcd8739ae039.varintBufNum(scriptLen).length + scriptLen;
  }
  _estimateSize() {
    let result = 5;
    result += this.inputs.length < 253 ? 1 : 3;
    this.inputs.forEach((input) => {
      result += input.estimateSize();
    });
    result += this.outputs.length < 253 ? 1 : 3;
    this.outputs.forEach((output) => {
      result += output.toBufferWriter().toBuffer().length;
    });
    return result;
  }
  _isMissingSignatures(opts) {
    if (opts?.disableIsFullySigned) return;
    if (!this.isFullySigned()) return new Error("Some inputs have not been fully signed");
  }
  isFullySigned() {
    if (this.inputs.some((input) => input.isFullySigned === $9b92277fa5d35484$export$2e2bcd8739ae039.prototype.isFullySigned)) throw new Error("Unable to verify signature: Unrecognized script kind, or not enough information to execute script. This usually happens when creating a transaction from a serialized transaction");
    return this.inputs.every((input) => input.isFullySigned());
  }
  /**
  * @returns true if the transaction has enough info on all inputs to be correctly validated
  */
  hasAllUtxoInfo() {
    return this.inputs.every((input) => !isUndefined(input.output));
  }
  getUnspentValue() {
    return this.inputAmount - this.outputAmount;
  }
  /**
  * Calculates the fee of the transaction.
  *
  * If there's a fixed fee set, return that.
  *
  * If there is no change output set, the fee is the
  * total value of the outputs minus inputs. Note that
  * a serialized transaction only specifies the value
  * of its outputs. (The value of inputs are recorded
  * in the previous transaction outputs being spent.)
  * This method therefore raises a "MissingPreviousOutput"
  * error when called on a serialized transaction.
  *
  * If there's no fee set and no change address,
  * estimate the fee based on size.
  *
  * @return fee of this transaction in satoshis
  */
  getFee() {
    if (this.isCoinbase()) return 0;
    if (!isUndefined(this._fee)) return this._fee;
    if (!this._changeScript) return Number(this.getUnspentValue());
    return this._estimateFee();
  }
  /**
  * Calculates the required fee of the transaction.
  * 
  * @remarks this method is different than getFee.
  *  while getFee return the current fee estimation, this method return how much fee is required according to the fee rate.
  * 
  * @returns the required fees of this transaction in satoshis
  */
  estimateRequiredFee() {
    let feeRate = this._feePerByte || $926e193f4c554367$export$2e2bcd8739ae039.FEE_PER_BYTE;
    return feeRate * this._estimateSize();
  }
  clearSignatures() {
    this.inputs.forEach((input) => input.clearSignatures());
  }
  /**
  * Retrieve a hexa string that can be used with nexad's CLI interface
  * (decoderawtransaction, sendrawtransaction)
  *
  * @param opts allows to skip certain tests.
  */
  checkedSerialize(opts) {
    let serializationError = this.getSerializationError(opts);
    if (serializationError) throw serializationError;
    return this.toString();
  }
  toString() {
    return this.toBuffer().toString("hex");
  }
  inspect() {
    return `<Transaction: ${this}>`;
  }
  fromString(string) {
    return this.fromBuffer(Buffer$1.from(string, "hex"));
  }
  /**
  * Retrieve a hexa string that can be used with nexad's CLI interface
  * (decoderawtransaction, sendrawtransaction)
  *
  * @param unsafe if true, skip all tests. if it's an object,
  * it's expected to contain a set of flags to skip certain tests.
  * 
  * @see {@link TxVerifyOptions}
  */
  serialize(unsafe) {
    if (true === unsafe || isObject$1(unsafe) && unsafe.disableAll) return this.uncheckedSerialize();
    else return this.checkedSerialize(isObject$1(unsafe) ? unsafe : void 0);
  }
  /**
  * Manually set the fee for this transaction. Beware that this resets all the signatures
  * for inputs.
  *
  * @param amount satoshis to be set as fees
  * @return this, for chaining
  */
  setFee(amount) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isNumber$1(amount), "amount must be a number");
    this._fee = amount;
    this._updateChangeOutput();
    return this;
  }
  /**
  * Manually set the fee per Byte for this transaction. Beware that this resets all the signatures
  * for inputs.
  * fee per Byte will be ignored if fee property was set manually
  *
  * @param amount satoshis per Byte to be used as fee rate
  * @return this, for chaining
  */
  setFeePerByte(amount) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isNumber$1(amount), "amount must be a number");
    this._feePerByte = amount;
    this._updateChangeOutput();
    return this;
  }
  /**
  * Add an output to the transaction.
  *
  * @param output the output to add.
  * @return this, for chaining
  */
  addOutput(output) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(output, $98955c312257c252$export$2e2bcd8739ae039, "output");
    this.outputs.push(output);
    this._updateChangeOutput();
    return this;
  }
  removeOutput(index) {
    this._removeOutput(index);
    this._updateChangeOutput();
    return this;
  }
  _removeOutput(index) {
    this.outputs = this.outputs.filter((_, i) => i !== index);
  }
  /**
  * Remove all outputs from the transaction.
  *
  * @return this, for chaining
  */
  clearOutputs() {
    this.outputs = [];
    this.clearSignatures();
    this._updateChangeOutput();
    return this;
  }
  updateOutputAmount(index, sats) {
    this.outputs[index].value = BigInt(sats);
    this._updateChangeOutput();
  }
  /**
  * Set the change address for this transaction
  *
  * Beware that this resets all the signatures for inputs.
  *
  * @param address An address for change to be sent to.
  * @return this, for chaining
  */
  setChangeOutput(address) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isNil(address), "address is required.");
    this._changeScript = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildOutFromAddress(address);
    this._updateChangeOutput();
    return this;
  }
  /**
  * @returns change output, if it exists
  */
  getChangeOutput() {
    if (!isUndefined(this._changeIndex)) return this.outputs[this._changeIndex];
    return void 0;
  }
  _updateChangeOutput() {
    if (!this._changeScript) return;
    this.clearSignatures();
    if (!isUndefined(this._changeIndex)) this._removeOutput(this._changeIndex);
    let available = this.getUnspentValue();
    let fee = this.getFee();
    let changeAmount = available - BigInt(fee);
    if (changeAmount >= $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT) {
      this._changeIndex = this.outputs.length;
      this.outputs.push(new $98955c312257c252$export$2e2bcd8739ae039(changeAmount, this._changeScript));
    } else this._changeIndex = void 0;
  }
  /**
  * Add an input to this transaction, without checking that the input has information about
  * the output that it's spending.
  *
  * @param input the input to add
  * @return this, for chaining
  */
  uncheckedAddInput(input) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(input, $9b92277fa5d35484$export$2e2bcd8739ae039, "input");
    this.inputs.push(input);
    this._updateChangeOutput();
    return this;
  }
  /**
  * Add an input to this transaction. The input must be an instance of the `Input` class.
  * It should have information about the Output that it's spending, but if it's not already
  * set, two additional parameters, `outputScript` and `amount` can be provided.
  *
  * @param input
  * @param outputScript
  * @param amount
  * @return this, for chaining
  */
  addInput(input, outputScript, amount) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgumentType(input, $9b92277fa5d35484$export$2e2bcd8739ae039, "input");
    if (isUndefined(input.output) && (isUndefined(outputScript) || isUndefined(amount))) throw new Error("Need information about the UTXO script and amount");
    if (isUndefined(input.output) && !isUndefined(outputScript) && !isUndefined(amount)) {
      let scriptPubKey = outputScript instanceof $90f45db77a786f2b$export$2e2bcd8739ae039 ? outputScript : new $90f45db77a786f2b$export$2e2bcd8739ae039(outputScript);
      input.output = new $98955c312257c252$export$2e2bcd8739ae039(BigInt(amount), scriptPubKey);
    }
    return this.uncheckedAddInput(input);
  }
  removeInput(outpoint) {
    this.inputs = this.inputs.filter((input) => input.outpoint.toString("hex") != outpoint);
    this._updateChangeOutput();
    return this;
  }
  /**
  * Sets nLockTime so that transaction is not valid until the desired date or height.
  * Beware that this method will also set the inputs sequence number to max_int - 1
  * 
  * @remarks nLockTime considered as height if the value is between 0 - 499,999,999.
  *  above that considered as date (unix timestamp).
  * 
  * @see {@link NLOCKTIME_BLOCKHEIGHT_LIMIT}
  * 
  * @param locktime 
  * @returns 
  */
  setLockTime(locktime) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isNumber$1(locktime), "locktime", "must be a number");
    this.inputs.forEach((input) => {
      if (input.sequenceNumber === $9b92277fa5d35484$export$2e2bcd8739ae039.SEQUENCE_FINAL) input.sequenceNumber = $9b92277fa5d35484$export$2e2bcd8739ae039.SEQUENCE_FINAL - 1;
    });
    this.nLockTime = locktime;
    return this;
  }
  /**
  *  Returns a semantic version of the transaction's nLockTime.
  *  If nLockTime is 0, it returns null,
  *  if it is < 500000000, it returns a block height (number)
  *  else it returns a Date object.
  */
  getLockTime() {
    if (!this.nLockTime) return null;
    if (this.nLockTime < $926e193f4c554367$export$2e2bcd8739ae039.NLOCKTIME_BLOCKHEIGHT_LIMIT) return this.nLockTime;
    return new Date(1e3 * this.nLockTime);
  }
  toBuffer() {
    return this.toBufferWriter().toBuffer();
  }
  toBufferWriter(writer, withInputsScripts = true) {
    if (!writer) writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    writer.writeUInt8(this.version);
    writer.writeVarintNum(this.inputs.length);
    this.inputs.forEach((input) => input.toBufferWriter(writer, withInputsScripts));
    writer.writeVarintNum(this.outputs.length);
    this.outputs.forEach((output) => output.toBufferWriter(writer));
    writer.writeUInt32LE(this.nLockTime);
    return writer;
  }
  _toIdemBuffer() {
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    return this.toBufferWriter(writer, false).toBuffer();
  }
  _toSatisfierBuffer() {
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    writer.writeInt32LE(this.inputs.length);
    this.inputs.forEach((input) => {
      writer.write(input.scriptSig.toBuffer());
      writer.writeUInt8($92c0719d4ab9ac45$export$393941f88fd16991.OP_INVALIDOPCODE);
    });
    return writer.toBuffer();
  }
  fromBuffer(buffer) {
    let reader = new $12fea2c2eb591556$export$2e2bcd8739ae039(buffer);
    return this.fromBufferReader(reader);
  }
  fromBufferReader(reader) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(!reader.finished(), "No transaction data received");
    this.version = reader.readUInt8();
    let sizeTxIns = reader.readVarintNum();
    for (let i = 0; i < sizeTxIns; i++) this.inputs.push($9b92277fa5d35484$export$2e2bcd8739ae039.fromBufferReader(reader));
    let sizeTxOuts = reader.readVarintNum();
    for (let i = 0; i < sizeTxOuts; i++) this.outputs.push($98955c312257c252$export$2e2bcd8739ae039.fromBufferReader(reader));
    this.nLockTime = reader.readUInt32LE();
    return this;
  }
  toObject() {
    let obj = {
      id: this.id,
      idem: this.idem,
      version: this.version,
      inputs: this.inputs.map((input) => input.toObject()),
      outputs: this.outputs.map((output) => output.toObject()),
      nLockTime: this.nLockTime
    };
    if (!isUndefined(this._changeScript)) obj.changeScript = this._changeScript.toHex();
    if (!isUndefined(this._changeIndex)) obj.changeIndex = this._changeIndex;
    if (!isUndefined(this._fee)) obj.fee = this._fee;
    if (!isUndefined(this._feePerByte)) obj.feePerByte = this._feePerByte;
    return obj;
  }
  fromObject(transaction) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(transaction), "transaction");
    if (transaction instanceof $926e193f4c554367$export$2e2bcd8739ae039) transaction = transaction.toObject();
    this.nLockTime = transaction.nLockTime;
    this.version = transaction.version;
    for (let input of transaction.inputs) {
      if (isUndefined(input.output?.scriptPubKey)) {
        this.uncheckedAddInput(new $9b92277fa5d35484$export$2e2bcd8739ae039(input));
        continue;
      }
      let script = new $90f45db77a786f2b$export$2e2bcd8739ae039(input.output.scriptPubKey);
      let txin;
      if (script.isPublicKeyHashOut()) txin = new $5cf2ce125ae8c2d7$export$2e2bcd8739ae039(input);
      else if (script.isPublicKeyTemplateOut()) txin = new $49712dfa37abdb5b$export$2e2bcd8739ae039(input);
      else if (script.isScriptTemplateOut()) {
        if ("templateData" in input) txin = new $6995bc57838749e2$export$2e2bcd8739ae039(input);
        else txin = new $9b92277fa5d35484$export$2e2bcd8739ae039(input);
      } else throw new Error(`Unsupported input script type: ${script}`);
      this.addInput(txin);
    }
    for (let output of transaction.outputs) this.addOutput($98955c312257c252$export$2e2bcd8739ae039.fromObject(output));
    if (!isUndefined(transaction.changeIndex)) this._changeIndex = transaction.changeIndex;
    if (!isUndefined(transaction.changeScript)) this._changeScript = new $90f45db77a786f2b$export$2e2bcd8739ae039(transaction.changeScript);
    if (!isUndefined(transaction.fee)) this._fee = transaction.fee;
    if (!isUndefined(transaction.feePerByte)) this._feePerByte = transaction.feePerByte;
    this._checkConsistency(transaction);
    return this;
  }
  _checkConsistency(transaction) {
    if (!isUndefined(this._changeIndex)) {
      $e44f707fde477092$export$2e2bcd8739ae039.validateState(!isUndefined(this._changeScript), "Change script is expected.");
      $e44f707fde477092$export$2e2bcd8739ae039.validateState(!isUndefined(this.outputs[this._changeIndex]), "Change index points to undefined output.");
      $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.outputs[this._changeIndex].scriptPubKey.toHex() === this._changeScript?.toHex(), "Change output has an unexpected script.");
    }
    if (transaction?.id) $e44f707fde477092$export$2e2bcd8739ae039.validateState(transaction.id === this.id, "Id in object does not match transaction id.");
  }
}
class $54bdedd720718511$export$2e2bcd8739ae039 {
  /**
  * Represents an unspent output information: its outpoint hash, associated amount/sats,
  * associated script or address with optional group info,
  *
  * @param utxo the utxo object
  * @param utxo.outpoint the outpoint hash
  * @param utxo.amount amount of nexa associated as string or number
  * @param utxo.satoshis alias for `amount`, but expressed in satoshis (1 NEXA = 100 satoshis) as bigint, string or number
  * @param utxo.scriptPubKey the script that must be resolved to release the funds
  * @param utxo.address optional. can be used instead of the full script
  * @param utxo.groupId optional. can be used instead of the full script
  * @param utxo.groupAmount optional. can be used instead of the full script
  */
  constructor(utxo) {
    this.toJSON = this.toObject;
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(utxo), "Must provide an object from where to extract data");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument($c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(utxo.outpoint), "Invalid outpoint hash");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(utxo.satoshis) || !isUndefined(utxo.amount), "Must provide satoshis or amount");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(utxo.scriptPubKey) || !isUndefined(utxo.address), "Must provide script or address");
    this.outpoint = utxo.outpoint;
    this.satoshis = !isUndefined(utxo.satoshis) ? BigInt(utxo.satoshis) : $05e660d5daa855e4$export$2e2bcd8739ae039.parseNEXA(utxo.amount.toString());
    this.scriptPubKey = !isUndefined(utxo.scriptPubKey) ? new $90f45db77a786f2b$export$2e2bcd8739ae039(utxo.scriptPubKey) : $fea109eb8128bf4c$export$2e2bcd8739ae039.buildOutFromAddress(utxo.address, utxo.groupId, utxo.groupAmount);
  }
  /**
  * String representation: just the outpoint hash
  */
  toString() {
    return this.outpoint;
  }
  /**
  * Provide an informative output when displaying this object in the console
  */
  inspect() {
    return `<UnspentOutput: ${this}, satoshis: ${this.satoshis}, script: ${this.scriptPubKey}>`;
  }
  /**
  * Deserialize an UnspentOutput from an object
  * @param data
  */
  static fromObject(data) {
    return new $54bdedd720718511$export$2e2bcd8739ae039(data);
  }
  /**
  * Returns a plain object (no prototype or methods) with the associated info for this utxo
  */
  toObject() {
    return {
      outpoint: this.outpoint,
      scriptPubKey: this.scriptPubKey.toHex(),
      amount: $05e660d5daa855e4$export$2e2bcd8739ae039.formatNEXA(this.satoshis)
    };
  }
}
class $6ebeca4bc214d833$export$2e2bcd8739ae039 {
  /**
  * Wrapper around Signature with fields related to signing a transaction specifically
  */
  constructor(arg) {
    this.toJSON = this.toObject;
    $6ebeca4bc214d833$export$2e2bcd8739ae039._validateArgs(arg);
    this.inputIndex = arg.inputIndex;
    this.publicKey = isString(arg.publicKey) ? $246eb589bb078d6d$export$2e2bcd8739ae039.fromString(arg.publicKey) : arg.publicKey;
    this.subscript = isString(arg.subscript) ? $90f45db77a786f2b$export$2e2bcd8739ae039.fromHex(arg.subscript) : arg.subscript;
    this.signature = isString(arg.signature) ? $369a157b63fbc3fd$export$2e2bcd8739ae039.fromString(arg.signature) : arg.signature;
    this.sigType = isString(arg.sigType) ? $e50a883097cd2090$export$2e2bcd8739ae039.fromString(arg.sigType) : arg.sigType;
  }
  static _validateArgs(arg) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(isObject$1(arg), "TxSignature must be instantiated from an object");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isNil(arg.publicKey) && !!$246eb589bb078d6d$export$2e2bcd8739ae039.from(arg.publicKey), "publicKey");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isNil(arg.inputIndex), "inputIndex");
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(isNumber$1(arg.inputIndex), "inputIndex must be a number");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isNil(arg.subscript), "subscript");
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(arg.subscript instanceof $90f45db77a786f2b$export$2e2bcd8739ae039 || $c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(arg.subscript), "subscript must be an object or hexa value");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isNil(arg.signature), "signature");
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(arg.signature instanceof $369a157b63fbc3fd$export$2e2bcd8739ae039 || $c337f7a9455509cf$export$2e2bcd8739ae039.isHexa(arg.signature), "signature must be an object or hexa value");
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(arg.sigType instanceof $e50a883097cd2090$export$2e2bcd8739ae039 || isString(arg.sigType), "sigtype must be a sigtype object or string");
  }
  toObject() {
    return {
      inputIndex: this.inputIndex,
      publicKey: this.publicKey.toString(),
      subscript: this.subscript.toHex(),
      signature: this.signature.toString(),
      sigType: this.sigType.toString()
    };
  }
  static fromObject(arg) {
    return new $6ebeca4bc214d833$export$2e2bcd8739ae039(arg);
  }
  toTxSatisfier() {
    return this.signature.toTxFormat(this.sigType.toBuffer());
  }
}
class $2dc9a1945ba915b1$export$2e2bcd8739ae039 {
  /**
  * Create a signature
  * 
  * @param transaction the transaction to sign
  * @param inputNumber the input index for the signature
  * @param sighashType the sighash type
  * @param subscript the script that will be signed
  * @param privateKey the privkey to sign with
  * @returns The signature
  */
  static sign(transaction, inputNumber, sighashType, subscript, privateKey) {
    let hashbuf = this.buildSighash(transaction, inputNumber, sighashType, subscript);
    return $1739481af0c86d04$export$2e2bcd8739ae039.sign(hashbuf, privateKey, "little");
  }
  /**
  * Verify a signature
  * 
  * @param transaction the transaction to verify
  * @param inputNumber the input index for the signature
  * @param signature the signature to verify
  * @param sighashType the sighash type
  * @param subscript the script that will be verified
  * @param publicKey the pubkey that correspond to the signing privkey
  * @returns true if signature is valid
  */
  static verify(transaction, inputNumber, signature, sighashType, subscript, publicKey) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(transaction), "transaction");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(signature), "signature");
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(sighashType), "sighashType");
    let hashbuf = this.buildSighash(transaction, inputNumber, sighashType, subscript);
    return $1739481af0c86d04$export$2e2bcd8739ae039.verify(hashbuf, signature, publicKey, "little");
  }
  /**
  * Returns a buffer of length 32 bytes with the hash that needs to be signed for OP_CHECKSIG(VERIFY).
  *
  * @param transaction the transaction to sign
  * @param inputNumber the input index for the signature
  * @param sighashType the sighash type
  * @param subscript the script that will be signed
  */
  static buildSighash(transaction, inputNumber, sighashType, subscript) {
    let components = this._getSighashComponents(transaction, inputNumber, sighashType);
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    writer.writeUInt8(transaction.version);
    writer.write(components.hashPrevouts);
    writer.write(components.hashInputAmounts);
    writer.write(components.hashSequence);
    writer.writeVarLengthBuf(subscript.toBuffer());
    writer.write(components.hashOutputs);
    writer.writeUInt32LE(transaction.nLockTime);
    writer.writeVarLengthBuf(sighashType.toBuffer());
    let buf = writer.toBuffer();
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf).reverse();
  }
  static _getSighashComponents(transaction, inputNumber, sighashType) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!sighashType.isInvalid(), "sighashType");
    let hashPrevouts, hashSequence, hashInputAmounts, hashOutputs;
    switch (sighashType.inType) {
      case $e50a883097cd2090$export$ae38be9ef660d12e.FIRSTN:
        let firstN = sighashType.inData[0];
        $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(firstN <= transaction.inputs.length, "firstN out of range");
        hashPrevouts = this._getPrevoutHash(transaction, firstN);
        hashSequence = this._getSequenceHash(transaction, firstN);
        hashInputAmounts = this._getInputAmountHash(transaction, firstN);
        break;
      case $e50a883097cd2090$export$ae38be9ef660d12e.THISIN:
        $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(inputNumber < transaction.inputs.length, "inputNumber out of range");
        hashPrevouts = this._getPrevoutHashOf(transaction, inputNumber);
        hashSequence = this._getSequenceHashOf(transaction, inputNumber);
        hashInputAmounts = this._getInputAmountHashOf(transaction, inputNumber);
        break;
      default:
        hashPrevouts = this._getPrevoutHash(transaction, transaction.inputs.length);
        hashSequence = this._getSequenceHash(transaction, transaction.inputs.length);
        hashInputAmounts = this._getInputAmountHash(transaction, transaction.inputs.length);
        break;
    }
    switch (sighashType.outType) {
      case $e50a883097cd2090$export$cc0d5ed6c4786851.FIRSTN:
        let firstN1 = sighashType.outData[0];
        $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(firstN1 <= transaction.outputs.length, "firstN out of range");
        hashOutputs = this._getOutputsHash(transaction, firstN1);
        break;
      case $e50a883097cd2090$export$cc0d5ed6c4786851.TWO:
        let [out1, out2] = sighashType.outData;
        $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(out1 < transaction.outputs.length, "out1 out of range");
        $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(out2 < transaction.outputs.length, "out2 out of range");
        hashOutputs = this._getOutputsHashOf(transaction, out1, out2);
        break;
      default:
        hashOutputs = this._getOutputsHash(transaction, transaction.outputs.length);
        break;
    }
    return {
      hashPrevouts,
      hashSequence,
      hashInputAmounts,
      hashOutputs
    };
  }
  static _getPrevoutHash(tx, firstN) {
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    for (let i = 0; i < firstN; i++) {
      writer.writeUInt8(tx.inputs[i].type);
      writer.writeReverse(tx.inputs[i].outpoint);
    }
    let buf = writer.toBuffer();
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf);
  }
  static _getPrevoutHashOf(tx, inputNumber) {
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    writer.writeUInt8(tx.inputs[inputNumber].type);
    writer.writeReverse(tx.inputs[inputNumber].outpoint);
    let buf = writer.toBuffer();
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf);
  }
  static _getSequenceHash(tx, firstN) {
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    for (let i = 0; i < firstN; i++) writer.writeUInt32LE(tx.inputs[i].sequenceNumber);
    let buf = writer.toBuffer();
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf);
  }
  static _getSequenceHashOf(tx, inputNumber) {
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    writer.writeUInt32LE(tx.inputs[inputNumber].sequenceNumber);
    let buf = writer.toBuffer();
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf);
  }
  static _getInputAmountHash(tx, firstN) {
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    for (let i = 0; i < firstN; i++) writer.writeUInt64LEBN($5aa97aebe18a7924$export$2e2bcd8739ae039.fromBigInt(tx.inputs[i].amount));
    let buf = writer.toBuffer();
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf);
  }
  static _getInputAmountHashOf(tx, inputNumber) {
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    writer.writeUInt64LEBN($5aa97aebe18a7924$export$2e2bcd8739ae039.fromBigInt(tx.inputs[inputNumber].amount));
    let buf = writer.toBuffer();
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf);
  }
  static _getOutputsHash(tx, firstN) {
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    for (let i = 0; i < firstN; i++) tx.outputs[i].toBufferWriter(writer);
    let buf = writer.toBuffer();
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf);
  }
  static _getOutputsHashOf(tx, out1, out2) {
    let writer = new $35852622c8c617e8$export$2e2bcd8739ae039();
    tx.outputs[out1].toBufferWriter(writer);
    tx.outputs[out2].toBufferWriter(writer);
    let buf = writer.toBuffer();
    return $62ca61b6ba036e1b$export$2e2bcd8739ae039.sha256sha256(buf);
  }
}
class $bd99faf64de54a2c$export$2e2bcd8739ae039 {
  constructor(tx) {
    if (tx instanceof $926e193f4c554367$export$2e2bcd8739ae039) this.transaction = tx;
    else this.transaction = new $926e193f4c554367$export$2e2bcd8739ae039(tx);
  }
  build() {
    return this.transaction;
  }
  /**
  * Add an input to this transaction. This is a high level interface
  * to add an input, for more control, use {@link Transaction.addInput}.
  *
  * Can receive, as output information, the output of nexad's `listunspent` command,
  * with a slightly fancier format recognized by this sdk:
  *
  * ```json
  * {
  *  outpoint: "fcf7d303d67f19568cf4ab72d36d583baac461e0f62f289b3dff68da96c2117c"
  *  scriptPubKey: "005114891c4b19cbcaefc31770a938ebd6b1fafabb1be6",
  *  satoshis: 181998351
  * }
  * // or alternative:
  * {
  *  outpoint: "fcf7d303d67f19568cf4ab72d36d583baac461e0f62f289b3dff68da96c2117c"
  *  address: "nexa:nqtsq5g53ywykxwtethux9ms4yuwh443ltatkxlx3s5pnvwh",
  *  amount: 1819983.51
  *  groupId: <token address if relevant>
  *  groupAmount: <token amount if relevant>
  * }
  * ```
  * Where `address` can be either a string or a nexcore Address object. The
  * same is true for `script`, which can be a string or a nexcore Script.
  * 
  * @see {@link UTXO}
  *
  * Beware that this resets all the signatures for inputs.
  *
  * @example
  * ```javascript
  * let builder = new TransactionBuilder();
  *
  * // From a pay to public key template output from nexad's listunspent
  * builder.from({'outpoint': '0000...', amount: 123.23, scriptPubKey: 'OP_0 OP_1 ...'});
  *
  * // From a pay to public key template output (with optional group data)
  * builder.from({'outpoint': '0000...', satoshis: 12323, address: 'nexa:nqtsq5g...', groupId? 'nexa:tnq...', groupAmount: 56446n });
  *
  * // From a script template output
  * builder.from({'outpoint': '0000...', satoshis: 1000, scriptPubKey: '...', templateData: { templateScript: '...', constraintScript: '...' }};
  * 
  * let transaction = builder.build();
  * ```
  * 
  * @param utxo details on the utxo
  * @returns this, for chaining
  */
  from(utxo) {
    if (isArray(utxo)) {
      utxo.forEach((u) => this.from(u));
      return this;
    }
    let exist = this.transaction.inputs.some((input) => input.outpoint.toString("hex") === utxo.outpoint);
    if (exist) return this;
    return this._fromUtxo(new $54bdedd720718511$export$2e2bcd8739ae039(utxo), utxo.templateData);
  }
  _fromUtxo(utxo, templateData) {
    let clazz;
    if (utxo.scriptPubKey.isPublicKeyHashOut()) clazz = $5cf2ce125ae8c2d7$export$2e2bcd8739ae039;
    else if (utxo.scriptPubKey.isPublicKeyTemplateOut()) clazz = $49712dfa37abdb5b$export$2e2bcd8739ae039;
    else if (utxo.scriptPubKey.isScriptTemplateOut() && isObject$1(templateData)) clazz = $6995bc57838749e2$export$2e2bcd8739ae039;
    else clazz = $9b92277fa5d35484$export$2e2bcd8739ae039;
    let input = new clazz({
      output: new $98955c312257c252$export$2e2bcd8739ae039(utxo.satoshis, utxo.scriptPubKey),
      outpoint: utxo.outpoint,
      scriptSig: $90f45db77a786f2b$export$2e2bcd8739ae039.empty(),
      amount: utxo.satoshis,
      templateData
    });
    this.transaction.addInput(input);
    return this;
  }
  /**
  * Add an output to the transaction.
  *
  * Beware that this resets all the signatures for inputs.
  *
  * @param address the destination address
  * @param amount in satoshis, the nexa amount
  * @param groupId optional. the token address if sending tokens
  * @param groupAmount optional. the token amount if sending tokens
  * 
  * @remarks if sending token, the nexa amount is usually {@link Transaction.DUST_AMOUNT}
  * 
  * @returns this, for chaining
  */
  to(address, amount, groupId, groupAmount) {
    let script = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildOutFromAddress(address, groupId, groupAmount);
    let output = new $98955c312257c252$export$2e2bcd8739ae039(amount, script);
    this.transaction.addOutput(output);
    return this;
  }
  /**
  * Add an OP_RETURN output to the transaction.
  *
  * Beware that this resets all the signatures for inputs.
  *
  * @param data the data to be stored in the OP_RETURN output.
  *    In case of a string, the UTF-8 representation will be stored
  * @param isFullScript if the provided data is already an op_return script. default false.
  * @returns this, for chaining
  */
  addData(data, isFullScript = false) {
    let script = isFullScript ? new $90f45db77a786f2b$export$2e2bcd8739ae039(data) : $fea109eb8128bf4c$export$2e2bcd8739ae039.buildDataOut(data);
    let output = new $98955c312257c252$export$2e2bcd8739ae039(0, script);
    this.transaction.addOutput(output);
    return this;
  }
  /**
  * Set the change address for this transaction
  *
  * Beware that this resets all the signatures for inputs.
  *
  * @param address An address for change to be sent to.
  * @returns this, for chaining
  */
  change(address) {
    this.transaction.setChangeOutput(address);
    return this;
  }
  /**
  * Manually set the fee for this transaction. 
  * 
  * Beware that this resets all the signatures for inputs.
  *
  * @param amount satoshis to be used as fee
  * @returns this, for chaining
  */
  fee(amount) {
    this.transaction.setFee(amount);
    return this;
  }
  /**
  * Manually set the fee per Byte rate for this transaction.
  * 
  * Beware that this resets all the signatures for inputs.
  * 
  * @remarks fee per Byte will be ignored if fee property was set manually
  *
  * @param amount satoshis per Byte to be used as fee rate
  * @returns this, for chaining
  */
  feePerByte(amount) {
    this.transaction.setFeePerByte(amount);
    return this;
  }
  /**
  * Sets nLockTime so that transaction is not valid until the desired date
  * 
  * (a timestamp in seconds since UNIX epoch is also accepted)
  *
  * @param datetime Date object or unix timestamp number
  * @returns this, for chaining
  */
  lockUntilDate(datetime) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(!isUndefined(datetime), "datetime");
    if (isNumber$1(datetime) && datetime < $926e193f4c554367$export$2e2bcd8739ae039.NLOCKTIME_BLOCKHEIGHT_LIMIT) throw new Error("Lock Time can't be earlier than UNIX date 500 000 000");
    if (isDate(datetime)) datetime = datetime.getTime() / 1e3;
    this.transaction.setLockTime(datetime);
    return this;
  }
  /**
  * Sets nLockTime so that transaction is not valid until the desired block height.
  *
  * @param height the block height
  * @returns this, for chaining
  */
  lockUntilBlockHeight(height) {
    if (height >= $926e193f4c554367$export$2e2bcd8739ae039.NLOCKTIME_BLOCKHEIGHT_LIMIT) throw new Error("Block Height can be at most 2^32 - 1");
    if (height < 0) throw new Error("Block Height cannot be negative");
    this.transaction.setLockTime(height);
    return this;
  }
  /**
  * Sign the transaction using one or more private keys.
  *
  * It tries to sign each input, verifying that the signature will be valid
  * (matches a public key). Usually this is the last step that should be used with the builder.
  * 
  * @remarks this method sign all inputs and outputs (sighash type ALL).
  *  
  * if you need to sign a specific input or partial transaction
  *  (create new or complete existing one), use {@link signInput} method.
  *
  * @param privateKey private key(s) that be used to sign
  * @returns this, for chaining
  */
  sign(privateKey) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.transaction.hasAllUtxoInfo(), "Not all utxo information is available to sign the transaction.");
    if (isArray(privateKey)) {
      privateKey.forEach((key) => this.sign(key));
      return this;
    }
    this._getSignatures(privateKey, $e50a883097cd2090$export$2e2bcd8739ae039.ALL).forEach((sig) => this._applySignature(sig));
    return this;
  }
  /**
  * Sign specific input using private key and sighash type.
  * 
  * Use sigtype to determine which parts of the transaction to sign.
  * 
  * @param input The input to sign. can be input index (number) or input outpoint hash (string)
  * @param privateKey private key that be used to sign
  * @param sigtype the sighash type to define which parts to include in the sighash
  * @returns this, for chaining
  */
  signInput(input, privateKey, sigtype) {
    if (isString(input)) input = this.transaction.inputs.findIndex((inp) => inp.outpoint.toString("hex") === input);
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(input >= 0 && input < this.transaction.inputs.length, "input", "out of range.");
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(this.transaction.inputs[input].canSign(privateKey), "The provided key cannot sign this input");
    let txSig = this._getSignature(input, privateKey, sigtype);
    this._applySignature(txSig);
    return this;
  }
  _getSignatures(privKey, sigtype) {
    $e44f707fde477092$export$2e2bcd8739ae039.validateArgument(privKey instanceof $9e7155c0d97105d3$export$2e2bcd8739ae039, "privKey", "not a private key");
    let signatures = [];
    for (let i = 0; i < this.transaction.inputs.length; i++) {
      if (!this.transaction.inputs[i].canSign(privKey)) continue;
      let txSig = this._getSignature(i, privKey, sigtype);
      signatures.push(txSig);
    }
    return signatures;
  }
  _getSignature(index, privKey, sigtype) {
    let subscript = this.transaction.inputs[index].getSubscript();
    return new $6ebeca4bc214d833$export$2e2bcd8739ae039({
      inputIndex: index,
      publicKey: privKey.publicKey,
      subscript,
      signature: $2dc9a1945ba915b1$export$2e2bcd8739ae039.sign(this.transaction, index, sigtype, subscript, privKey),
      sigType: sigtype
    });
  }
  _applySignature(signature) {
    let isValid = $2dc9a1945ba915b1$export$2e2bcd8739ae039.verify(this.transaction, signature.inputIndex, signature.signature, signature.sigType, signature.subscript, signature.publicKey);
    $e44f707fde477092$export$2e2bcd8739ae039.validateState(isValid, "Signature is invalid");
    this.transaction.inputs[signature.inputIndex].addSignature(signature);
  }
}
function $149c1bd638913645$var$versionGuard$1(version) {
  if (version !== void 0) {
    let message = "More than one instance of libnexa found. Please make sure to require libnexa and check that submodules do not also include their own libnexa dependency.";
    throw new Error(message);
  }
}
$149c1bd638913645$var$versionGuard$1($parcel$global$1._libnexa_ver);
$parcel$global$1._libnexa_ver = `v${$df64573ef6d51081$exports$1.version}`;
const $149c1bd638913645$export$2e8191f482a38ccd = $a89918d61ea4dca0$export$2e2bcd8739ae039.getInstance();
({
  version: `v${$df64573ef6d51081$exports$1.version}`,
  Networks: $a89918d61ea4dca0$export$2e2bcd8739ae039.getInstance()
});
var src = {};
const crypto$1 = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function u8(arr) {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function rotl(word, shift) {
  return word << shift | word >>> 32 - shift >>> 0;
}
const isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
const swap8IfBE = isLE ? (n) => n : (n) => byteSwap(n);
const byteSwapIfBE = swap8IfBE;
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
const swap32IfBE = isLE ? (u) => u : byteSwap32;
const hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  if (hasHexBuiltin)
    return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
const nextTick = async () => {
};
async function asyncLoop(iters, tick, cb) {
  let ts = Date.now();
  for (let i = 0; i < iters; i++) {
    cb(i);
    const diff = Date.now() - ts;
    if (diff >= 0 && diff < tick)
      continue;
    await nextTick();
    ts += diff;
  }
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function kdfInputToBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad2 = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad2);
    pad2 += a.length;
  }
  return res;
}
function checkOpts(defaults, opts) {
  if (opts !== void 0 && {}.toString.call(opts) !== "[object Object]")
    throw new Error("options should be object or undefined");
  const merged = Object.assign(defaults, opts);
  return merged;
}
class Hash {
}
function createHasher(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function createOptHasher(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  return hashC;
}
function createXOFer(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  return hashC;
}
const wrapConstructor = createHasher;
const wrapConstructorWithOpts = createOptHasher;
const wrapXOFConstructorWithOpts = createXOFer;
function randomBytes(bytesLength = 32) {
  if (crypto$1 && typeof crypto$1.getRandomValues === "function") {
    return crypto$1.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto$1 && typeof crypto$1.randomBytes === "function") {
    return Uint8Array.from(crypto$1.randomBytes(bytesLength));
  }
  throw new Error("crypto.getRandomValues must be defined");
}
const utils = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  Hash,
  abytes,
  aexists,
  ahash,
  anumber,
  aoutput,
  asyncLoop,
  byteSwap,
  byteSwap32,
  byteSwapIfBE,
  bytesToHex,
  bytesToUtf8,
  checkOpts,
  clean,
  concatBytes,
  createHasher,
  createOptHasher,
  createView,
  createXOFer,
  hexToBytes,
  isBytes,
  isLE,
  kdfInputToBytes,
  nextTick,
  randomBytes,
  rotl,
  rotr,
  swap32IfBE,
  swap8IfBE,
  toBytes,
  u32,
  u8,
  utf8ToBytes,
  wrapConstructor,
  wrapConstructorWithOpts,
  wrapXOFConstructorWithOpts
}, Symbol.toStringTag, { value: "Module" }));
function setBigUint64(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n2 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n2 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
class HashMD extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    super();
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    data = toBytes(data);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor());
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
}
const SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
const SHA224_IV = /* @__PURE__ */ Uint32Array.from([
  3238371032,
  914150663,
  812702999,
  4144912697,
  4290775857,
  1750603025,
  1694076839,
  3204075428
]);
const SHA384_IV = /* @__PURE__ */ Uint32Array.from([
  3418070365,
  3238371032,
  1654270250,
  914150663,
  2438529370,
  812702999,
  355462360,
  4144912697,
  1731405415,
  4290775857,
  2394180231,
  1750603025,
  3675008525,
  1694076839,
  1203062813,
  3204075428
]);
const SHA512_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
]);
const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
const shrSH = (h, _l, s) => h >>> s;
const shrSL = (h, l, s) => h << 32 - s | l >>> s;
const rotrSH = (h, l, s) => h >>> s | l << 32 - s;
const rotrSL = (h, l, s) => h << 32 - s | l >>> s;
const rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
const rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
const add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
const add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
const SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
let SHA256$1 = class SHA256 extends HashMD {
  constructor(outputLen = 32) {
    super(64, outputLen, 8, false);
    this.A = SHA256_IV[0] | 0;
    this.B = SHA256_IV[1] | 0;
    this.C = SHA256_IV[2] | 0;
    this.D = SHA256_IV[3] | 0;
    this.E = SHA256_IV[4] | 0;
    this.F = SHA256_IV[5] | 0;
    this.G = SHA256_IV[6] | 0;
    this.H = SHA256_IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
let SHA224$1 = class SHA224 extends SHA256$1 {
  constructor() {
    super(28);
    this.A = SHA224_IV[0] | 0;
    this.B = SHA224_IV[1] | 0;
    this.C = SHA224_IV[2] | 0;
    this.D = SHA224_IV[3] | 0;
    this.E = SHA224_IV[4] | 0;
    this.F = SHA224_IV[5] | 0;
    this.G = SHA224_IV[6] | 0;
    this.H = SHA224_IV[7] | 0;
  }
};
const K512 = /* @__PURE__ */ (() => split([
  "0x428a2f98d728ae22",
  "0x7137449123ef65cd",
  "0xb5c0fbcfec4d3b2f",
  "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538",
  "0x59f111f1b605d019",
  "0x923f82a4af194f9b",
  "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242",
  "0x12835b0145706fbe",
  "0x243185be4ee4b28c",
  "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f",
  "0x80deb1fe3b1696b1",
  "0x9bdc06a725c71235",
  "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2",
  "0xefbe4786384f25e3",
  "0x0fc19dc68b8cd5b5",
  "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275",
  "0x4a7484aa6ea6e483",
  "0x5cb0a9dcbd41fbd4",
  "0x76f988da831153b5",
  "0x983e5152ee66dfab",
  "0xa831c66d2db43210",
  "0xb00327c898fb213f",
  "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2",
  "0xd5a79147930aa725",
  "0x06ca6351e003826f",
  "0x142929670a0e6e70",
  "0x27b70a8546d22ffc",
  "0x2e1b21385c26c926",
  "0x4d2c6dfc5ac42aed",
  "0x53380d139d95b3df",
  "0x650a73548baf63de",
  "0x766a0abb3c77b2a8",
  "0x81c2c92e47edaee6",
  "0x92722c851482353b",
  "0xa2bfe8a14cf10364",
  "0xa81a664bbc423001",
  "0xc24b8b70d0f89791",
  "0xc76c51a30654be30",
  "0xd192e819d6ef5218",
  "0xd69906245565a910",
  "0xf40e35855771202a",
  "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8",
  "0x1e376c085141ab53",
  "0x2748774cdf8eeb99",
  "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63",
  "0x4ed8aa4ae3418acb",
  "0x5b9cca4f7763e373",
  "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc",
  "0x78a5636f43172f60",
  "0x84c87814a1f0ab72",
  "0x8cc702081a6439ec",
  "0x90befffa23631e28",
  "0xa4506cebde82bde9",
  "0xbef9a3f7b2c67915",
  "0xc67178f2e372532b",
  "0xca273eceea26619c",
  "0xd186b8c721c0c207",
  "0xeada7dd6cde0eb1e",
  "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba",
  "0x0a637dc5a2c898a6",
  "0x113f9804bef90dae",
  "0x1b710b35131c471b",
  "0x28db77f523047d84",
  "0x32caab7b40c72493",
  "0x3c9ebe0a15c9bebc",
  "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6",
  "0x597f299cfc657e2a",
  "0x5fcb6fab3ad6faec",
  "0x6c44198c4a475817"
].map((n) => BigInt(n))))();
const SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
const SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
const SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
const SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
let SHA512$1 = class SHA512 extends HashMD {
  constructor(outputLen = 64) {
    super(128, outputLen, 16, false);
    this.Ah = SHA512_IV[0] | 0;
    this.Al = SHA512_IV[1] | 0;
    this.Bh = SHA512_IV[2] | 0;
    this.Bl = SHA512_IV[3] | 0;
    this.Ch = SHA512_IV[4] | 0;
    this.Cl = SHA512_IV[5] | 0;
    this.Dh = SHA512_IV[6] | 0;
    this.Dl = SHA512_IV[7] | 0;
    this.Eh = SHA512_IV[8] | 0;
    this.El = SHA512_IV[9] | 0;
    this.Fh = SHA512_IV[10] | 0;
    this.Fl = SHA512_IV[11] | 0;
    this.Gh = SHA512_IV[12] | 0;
    this.Gl = SHA512_IV[13] | 0;
    this.Hh = SHA512_IV[14] | 0;
    this.Hl = SHA512_IV[15] | 0;
  }
  // prettier-ignore
  get() {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset);
      SHA512_W_L[i] = view.getUint32(offset += 4);
    }
    for (let i = 16; i < 80; i++) {
      const W15h = SHA512_W_H[i - 15] | 0;
      const W15l = SHA512_W_L[i - 15] | 0;
      const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
      const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
      const W2h = SHA512_W_H[i - 2] | 0;
      const W2l = SHA512_W_L[i - 2] | 0;
      const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
      const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
      const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
      const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
      SHA512_W_H[i] = SUMh | 0;
      SHA512_W_L[i] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    for (let i = 0; i < 80; i++) {
      const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
      const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
      const CHIh = Eh & Fh ^ ~Eh & Gh;
      const CHIl = El & Fl ^ ~El & Gl;
      const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
      const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
      const T1l = T1ll | 0;
      const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
      const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
      const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
      const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = add3L(T1l, sigma0l, MAJl);
      Ah = add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  roundClean() {
    clean(SHA512_W_H, SHA512_W_L);
  }
  destroy() {
    clean(this.buffer);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
let SHA384$1 = class SHA384 extends SHA512$1 {
  constructor() {
    super(48);
    this.Ah = SHA384_IV[0] | 0;
    this.Al = SHA384_IV[1] | 0;
    this.Bh = SHA384_IV[2] | 0;
    this.Bl = SHA384_IV[3] | 0;
    this.Ch = SHA384_IV[4] | 0;
    this.Cl = SHA384_IV[5] | 0;
    this.Dh = SHA384_IV[6] | 0;
    this.Dl = SHA384_IV[7] | 0;
    this.Eh = SHA384_IV[8] | 0;
    this.El = SHA384_IV[9] | 0;
    this.Fh = SHA384_IV[10] | 0;
    this.Fl = SHA384_IV[11] | 0;
    this.Gh = SHA384_IV[12] | 0;
    this.Gl = SHA384_IV[13] | 0;
    this.Hh = SHA384_IV[14] | 0;
    this.Hl = SHA384_IV[15] | 0;
  }
};
const T224_IV = /* @__PURE__ */ Uint32Array.from([
  2352822216,
  424955298,
  1944164710,
  2312950998,
  502970286,
  855612546,
  1738396948,
  1479516111,
  258812777,
  2077511080,
  2011393907,
  79989058,
  1067287976,
  1780299464,
  286451373,
  2446758561
]);
const T256_IV = /* @__PURE__ */ Uint32Array.from([
  573645204,
  4230739756,
  2673172387,
  3360449730,
  596883563,
  1867755857,
  2520282905,
  1497426621,
  2519219938,
  2827943907,
  3193839141,
  1401305490,
  721525244,
  746961066,
  246885852,
  2177182882
]);
let SHA512_224$1 = class SHA512_224 extends SHA512$1 {
  constructor() {
    super(28);
    this.Ah = T224_IV[0] | 0;
    this.Al = T224_IV[1] | 0;
    this.Bh = T224_IV[2] | 0;
    this.Bl = T224_IV[3] | 0;
    this.Ch = T224_IV[4] | 0;
    this.Cl = T224_IV[5] | 0;
    this.Dh = T224_IV[6] | 0;
    this.Dl = T224_IV[7] | 0;
    this.Eh = T224_IV[8] | 0;
    this.El = T224_IV[9] | 0;
    this.Fh = T224_IV[10] | 0;
    this.Fl = T224_IV[11] | 0;
    this.Gh = T224_IV[12] | 0;
    this.Gl = T224_IV[13] | 0;
    this.Hh = T224_IV[14] | 0;
    this.Hl = T224_IV[15] | 0;
  }
};
let SHA512_256$1 = class SHA512_256 extends SHA512$1 {
  constructor() {
    super(32);
    this.Ah = T256_IV[0] | 0;
    this.Al = T256_IV[1] | 0;
    this.Bh = T256_IV[2] | 0;
    this.Bl = T256_IV[3] | 0;
    this.Ch = T256_IV[4] | 0;
    this.Cl = T256_IV[5] | 0;
    this.Dh = T256_IV[6] | 0;
    this.Dl = T256_IV[7] | 0;
    this.Eh = T256_IV[8] | 0;
    this.El = T256_IV[9] | 0;
    this.Fh = T256_IV[10] | 0;
    this.Fl = T256_IV[11] | 0;
    this.Gh = T256_IV[12] | 0;
    this.Gl = T256_IV[13] | 0;
    this.Hh = T256_IV[14] | 0;
    this.Hl = T256_IV[15] | 0;
  }
};
const sha256$2 = /* @__PURE__ */ createHasher(() => new SHA256$1());
const sha224$1 = /* @__PURE__ */ createHasher(() => new SHA224$1());
const sha512$2 = /* @__PURE__ */ createHasher(() => new SHA512$1());
const sha384$1 = /* @__PURE__ */ createHasher(() => new SHA384$1());
const sha512_256$1 = /* @__PURE__ */ createHasher(() => new SHA512_256$1());
const sha512_224$1 = /* @__PURE__ */ createHasher(() => new SHA512_224$1());
const SHA2562 = SHA256$1;
const sha256 = sha256$2;
const SHA2242 = SHA224$1;
const sha224 = sha224$1;
const sha256$1 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  SHA224: SHA2242,
  SHA256: SHA2562,
  sha224,
  sha256
}, Symbol.toStringTag, { value: "Module" }));
const require$$0$1 = /* @__PURE__ */ getAugmentedNamespace(sha256$1);
const SHA5122 = SHA512$1;
const sha512 = sha512$2;
const SHA3842 = SHA384$1;
const sha384 = sha384$1;
const SHA512_2242 = SHA512_224$1;
const sha512_224 = sha512_224$1;
const SHA512_2562 = SHA512_256$1;
const sha512_256 = sha512_256$1;
const sha512$1 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  SHA384: SHA3842,
  SHA512: SHA5122,
  SHA512_224: SHA512_2242,
  SHA512_256: SHA512_2562,
  sha384,
  sha512,
  sha512_224,
  sha512_256
}, Symbol.toStringTag, { value: "Module" }));
const require$$1$1 = /* @__PURE__ */ getAugmentedNamespace(sha512$1);
class HMAC extends Hash {
  constructor(hash, _key) {
    super();
    this.finished = false;
    this.destroyed = false;
    ahash(hash);
    const key = toBytes(_key);
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad2 = new Uint8Array(blockLen);
    pad2.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad2.length; i++)
      pad2[i] ^= 54;
    this.iHash.update(pad2);
    this.oHash = hash.create();
    for (let i = 0; i < pad2.length; i++)
      pad2[i] ^= 54 ^ 92;
    this.oHash.update(pad2);
    clean(pad2);
  }
  update(buf) {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists(this);
    abytes(out, this.outputLen);
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to || (to = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
}
const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new HMAC(hash, key);
function pbkdf2Init(hash, _password, _salt, _opts) {
  ahash(hash);
  const opts = checkOpts({ dkLen: 32, asyncTick: 10 }, _opts);
  const { c, dkLen, asyncTick } = opts;
  anumber(c);
  anumber(dkLen);
  anumber(asyncTick);
  if (c < 1)
    throw new Error("iterations (c) should be >= 1");
  const password = kdfInputToBytes(_password);
  const salt = kdfInputToBytes(_salt);
  const DK = new Uint8Array(dkLen);
  const PRF = hmac.create(hash, password);
  const PRFSalt = PRF._cloneInto().update(salt);
  return { c, dkLen, asyncTick, DK, PRF, PRFSalt };
}
function pbkdf2Output(PRF, PRFSalt, DK, prfW, u) {
  PRF.destroy();
  PRFSalt.destroy();
  if (prfW)
    prfW.destroy();
  clean(u);
  return DK;
}
function pbkdf2(hash, password, salt, opts) {
  const { c, dkLen, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
  let prfW;
  const arr = new Uint8Array(4);
  const view = createView(arr);
  const u = new Uint8Array(PRF.outputLen);
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
    const Ti = DK.subarray(pos, pos + PRF.outputLen);
    view.setInt32(0, ti, false);
    (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
    Ti.set(u.subarray(0, Ti.length));
    for (let ui = 1; ui < c; ui++) {
      PRF._cloneInto(prfW).update(u).digestInto(u);
      for (let i = 0; i < Ti.length; i++)
        Ti[i] ^= u[i];
    }
  }
  return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}
async function pbkdf2Async(hash, password, salt, opts) {
  const { c, dkLen, asyncTick, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
  let prfW;
  const arr = new Uint8Array(4);
  const view = createView(arr);
  const u = new Uint8Array(PRF.outputLen);
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
    const Ti = DK.subarray(pos, pos + PRF.outputLen);
    view.setInt32(0, ti, false);
    (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
    Ti.set(u.subarray(0, Ti.length));
    await asyncLoop(c - 1, asyncTick, () => {
      PRF._cloneInto(prfW).update(u).digestInto(u);
      for (let i = 0; i < Ti.length; i++)
        Ti[i] ^= u[i];
    });
  }
  return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}
const pbkdf2$1 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  pbkdf2,
  pbkdf2Async
}, Symbol.toStringTag, { value: "Module" }));
const require$$2$1 = /* @__PURE__ */ getAugmentedNamespace(pbkdf2$1);
const require$$3$1 = /* @__PURE__ */ getAugmentedNamespace(utils);
var _wordlists = {};
const require$$0 = /* @__PURE__ */ JSON.parse('["abdikace","abeceda","adresa","agrese","akce","aktovka","alej","alkohol","amputace","ananas","andulka","anekdota","anketa","antika","anulovat","archa","arogance","asfalt","asistent","aspirace","astma","astronom","atlas","atletika","atol","autobus","azyl","babka","bachor","bacil","baculka","badatel","bageta","bagr","bahno","bakterie","balada","baletka","balkon","balonek","balvan","balza","bambus","bankomat","barbar","baret","barman","baroko","barva","baterka","batoh","bavlna","bazalka","bazilika","bazuka","bedna","beran","beseda","bestie","beton","bezinka","bezmoc","beztak","bicykl","bidlo","biftek","bikiny","bilance","biograf","biolog","bitva","bizon","blahobyt","blatouch","blecha","bledule","blesk","blikat","blizna","blokovat","bloudit","blud","bobek","bobr","bodlina","bodnout","bohatost","bojkot","bojovat","bokorys","bolest","borec","borovice","bota","boubel","bouchat","bouda","boule","bourat","boxer","bradavka","brambora","branka","bratr","brepta","briketa","brko","brloh","bronz","broskev","brunetka","brusinka","brzda","brzy","bublina","bubnovat","buchta","buditel","budka","budova","bufet","bujarost","bukvice","buldok","bulva","bunda","bunkr","burza","butik","buvol","buzola","bydlet","bylina","bytovka","bzukot","capart","carevna","cedr","cedule","cejch","cejn","cela","celer","celkem","celnice","cenina","cennost","cenovka","centrum","cenzor","cestopis","cetka","chalupa","chapadlo","charita","chata","chechtat","chemie","chichot","chirurg","chlad","chleba","chlubit","chmel","chmura","chobot","chochol","chodba","cholera","chomout","chopit","choroba","chov","chrapot","chrlit","chrt","chrup","chtivost","chudina","chutnat","chvat","chvilka","chvost","chyba","chystat","chytit","cibule","cigareta","cihelna","cihla","cinkot","cirkus","cisterna","citace","citrus","cizinec","cizost","clona","cokoliv","couvat","ctitel","ctnost","cudnost","cuketa","cukr","cupot","cvaknout","cval","cvik","cvrkot","cyklista","daleko","dareba","datel","datum","dcera","debata","dechovka","decibel","deficit","deflace","dekl","dekret","demokrat","deprese","derby","deska","detektiv","dikobraz","diktovat","dioda","diplom","disk","displej","divadlo","divoch","dlaha","dlouho","dluhopis","dnes","dobro","dobytek","docent","dochutit","dodnes","dohled","dohoda","dohra","dojem","dojnice","doklad","dokola","doktor","dokument","dolar","doleva","dolina","doma","dominant","domluvit","domov","donutit","dopad","dopis","doplnit","doposud","doprovod","dopustit","dorazit","dorost","dort","dosah","doslov","dostatek","dosud","dosyta","dotaz","dotek","dotknout","doufat","doutnat","dovozce","dozadu","doznat","dozorce","drahota","drak","dramatik","dravec","draze","drdol","drobnost","drogerie","drozd","drsnost","drtit","drzost","duben","duchovno","dudek","duha","duhovka","dusit","dusno","dutost","dvojice","dvorec","dynamit","ekolog","ekonomie","elektron","elipsa","email","emise","emoce","empatie","epizoda","epocha","epopej","epos","esej","esence","eskorta","eskymo","etiketa","euforie","evoluce","exekuce","exkurze","expedice","exploze","export","extrakt","facka","fajfka","fakulta","fanatik","fantazie","farmacie","favorit","fazole","federace","fejeton","fenka","fialka","figurant","filozof","filtr","finance","finta","fixace","fjord","flanel","flirt","flotila","fond","fosfor","fotbal","fotka","foton","frakce","freska","fronta","fukar","funkce","fyzika","galeje","garant","genetika","geolog","gilotina","glazura","glejt","golem","golfista","gotika","graf","gramofon","granule","grep","gril","grog","groteska","guma","hadice","hadr","hala","halenka","hanba","hanopis","harfa","harpuna","havran","hebkost","hejkal","hejno","hejtman","hektar","helma","hematom","herec","herna","heslo","hezky","historik","hladovka","hlasivky","hlava","hledat","hlen","hlodavec","hloh","hloupost","hltat","hlubina","hluchota","hmat","hmota","hmyz","hnis","hnojivo","hnout","hoblina","hoboj","hoch","hodiny","hodlat","hodnota","hodovat","hojnost","hokej","holinka","holka","holub","homole","honitba","honorace","horal","horda","horizont","horko","horlivec","hormon","hornina","horoskop","horstvo","hospoda","hostina","hotovost","houba","houf","houpat","houska","hovor","hradba","hranice","hravost","hrazda","hrbolek","hrdina","hrdlo","hrdost","hrnek","hrobka","hromada","hrot","hrouda","hrozen","hrstka","hrubost","hryzat","hubenost","hubnout","hudba","hukot","humr","husita","hustota","hvozd","hybnost","hydrant","hygiena","hymna","hysterik","idylka","ihned","ikona","iluze","imunita","infekce","inflace","inkaso","inovace","inspekce","internet","invalida","investor","inzerce","ironie","jablko","jachta","jahoda","jakmile","jakost","jalovec","jantar","jarmark","jaro","jasan","jasno","jatka","javor","jazyk","jedinec","jedle","jednatel","jehlan","jekot","jelen","jelito","jemnost","jenom","jepice","jeseter","jevit","jezdec","jezero","jinak","jindy","jinoch","jiskra","jistota","jitrnice","jizva","jmenovat","jogurt","jurta","kabaret","kabel","kabinet","kachna","kadet","kadidlo","kahan","kajak","kajuta","kakao","kaktus","kalamita","kalhoty","kalibr","kalnost","kamera","kamkoliv","kamna","kanibal","kanoe","kantor","kapalina","kapela","kapitola","kapka","kaple","kapota","kapr","kapusta","kapybara","karamel","karotka","karton","kasa","katalog","katedra","kauce","kauza","kavalec","kazajka","kazeta","kazivost","kdekoliv","kdesi","kedluben","kemp","keramika","kino","klacek","kladivo","klam","klapot","klasika","klaun","klec","klenba","klepat","klesnout","klid","klima","klisna","klobouk","klokan","klopa","kloub","klubovna","klusat","kluzkost","kmen","kmitat","kmotr","kniha","knot","koalice","koberec","kobka","kobliha","kobyla","kocour","kohout","kojenec","kokos","koktejl","kolaps","koleda","kolize","kolo","komando","kometa","komik","komnata","komora","kompas","komunita","konat","koncept","kondice","konec","konfese","kongres","konina","konkurs","kontakt","konzerva","kopanec","kopie","kopnout","koprovka","korbel","korektor","kormidlo","koroptev","korpus","koruna","koryto","korzet","kosatec","kostka","kotel","kotleta","kotoul","koukat","koupelna","kousek","kouzlo","kovboj","koza","kozoroh","krabice","krach","krajina","kralovat","krasopis","kravata","kredit","krejcar","kresba","kreveta","kriket","kritik","krize","krkavec","krmelec","krmivo","krocan","krok","kronika","kropit","kroupa","krovka","krtek","kruhadlo","krupice","krutost","krvinka","krychle","krypta","krystal","kryt","kudlanka","kufr","kujnost","kukla","kulajda","kulich","kulka","kulomet","kultura","kuna","kupodivu","kurt","kurzor","kutil","kvalita","kvasinka","kvestor","kynolog","kyselina","kytara","kytice","kytka","kytovec","kyvadlo","labrador","lachtan","ladnost","laik","lakomec","lamela","lampa","lanovka","lasice","laso","lastura","latinka","lavina","lebka","leckdy","leden","lednice","ledovka","ledvina","legenda","legie","legrace","lehce","lehkost","lehnout","lektvar","lenochod","lentilka","lepenka","lepidlo","letadlo","letec","letmo","letokruh","levhart","levitace","levobok","libra","lichotka","lidojed","lidskost","lihovina","lijavec","lilek","limetka","linie","linka","linoleum","listopad","litina","litovat","lobista","lodivod","logika","logoped","lokalita","loket","lomcovat","lopata","lopuch","lord","losos","lotr","loudal","louh","louka","louskat","lovec","lstivost","lucerna","lucifer","lump","lusk","lustrace","lvice","lyra","lyrika","lysina","madam","madlo","magistr","mahagon","majetek","majitel","majorita","makak","makovice","makrela","malba","malina","malovat","malvice","maminka","mandle","manko","marnost","masakr","maskot","masopust","matice","matrika","maturita","mazanec","mazivo","mazlit","mazurka","mdloba","mechanik","meditace","medovina","melasa","meloun","mentolka","metla","metoda","metr","mezera","migrace","mihnout","mihule","mikina","mikrofon","milenec","milimetr","milost","mimika","mincovna","minibar","minomet","minulost","miska","mistr","mixovat","mladost","mlha","mlhovina","mlok","mlsat","mluvit","mnich","mnohem","mobil","mocnost","modelka","modlitba","mohyla","mokro","molekula","momentka","monarcha","monokl","monstrum","montovat","monzun","mosaz","moskyt","most","motivace","motorka","motyka","moucha","moudrost","mozaika","mozek","mozol","mramor","mravenec","mrkev","mrtvola","mrzet","mrzutost","mstitel","mudrc","muflon","mulat","mumie","munice","muset","mutace","muzeum","muzikant","myslivec","mzda","nabourat","nachytat","nadace","nadbytek","nadhoz","nadobro","nadpis","nahlas","nahnat","nahodile","nahradit","naivita","najednou","najisto","najmout","naklonit","nakonec","nakrmit","nalevo","namazat","namluvit","nanometr","naoko","naopak","naostro","napadat","napevno","naplnit","napnout","naposled","naprosto","narodit","naruby","narychlo","nasadit","nasekat","naslepo","nastat","natolik","navenek","navrch","navzdory","nazvat","nebe","nechat","necky","nedaleko","nedbat","neduh","negace","nehet","nehoda","nejen","nejprve","neklid","nelibost","nemilost","nemoc","neochota","neonka","nepokoj","nerost","nerv","nesmysl","nesoulad","netvor","neuron","nevina","nezvykle","nicota","nijak","nikam","nikdy","nikl","nikterak","nitro","nocleh","nohavice","nominace","nora","norek","nositel","nosnost","nouze","noviny","novota","nozdra","nuda","nudle","nuget","nutit","nutnost","nutrie","nymfa","obal","obarvit","obava","obdiv","obec","obehnat","obejmout","obezita","obhajoba","obilnice","objasnit","objekt","obklopit","oblast","oblek","obliba","obloha","obluda","obnos","obohatit","obojek","obout","obrazec","obrna","obruba","obrys","obsah","obsluha","obstarat","obuv","obvaz","obvinit","obvod","obvykle","obyvatel","obzor","ocas","ocel","ocenit","ochladit","ochota","ochrana","ocitnout","odboj","odbyt","odchod","odcizit","odebrat","odeslat","odevzdat","odezva","odhadce","odhodit","odjet","odjinud","odkaz","odkoupit","odliv","odluka","odmlka","odolnost","odpad","odpis","odplout","odpor","odpustit","odpykat","odrazka","odsoudit","odstup","odsun","odtok","odtud","odvaha","odveta","odvolat","odvracet","odznak","ofina","ofsajd","ohlas","ohnisko","ohrada","ohrozit","ohryzek","okap","okenice","oklika","okno","okouzlit","okovy","okrasa","okres","okrsek","okruh","okupant","okurka","okusit","olejnina","olizovat","omak","omeleta","omezit","omladina","omlouvat","omluva","omyl","onehdy","opakovat","opasek","operace","opice","opilost","opisovat","opora","opozice","opravdu","oproti","orbital","orchestr","orgie","orlice","orloj","ortel","osada","oschnout","osika","osivo","oslava","oslepit","oslnit","oslovit","osnova","osoba","osolit","ospalec","osten","ostraha","ostuda","ostych","osvojit","oteplit","otisk","otop","otrhat","otrlost","otrok","otruby","otvor","ovanout","ovar","oves","ovlivnit","ovoce","oxid","ozdoba","pachatel","pacient","padouch","pahorek","pakt","palanda","palec","palivo","paluba","pamflet","pamlsek","panenka","panika","panna","panovat","panstvo","pantofle","paprika","parketa","parodie","parta","paruka","paryba","paseka","pasivita","pastelka","patent","patrona","pavouk","pazneht","pazourek","pecka","pedagog","pejsek","peklo","peloton","penalta","pendrek","penze","periskop","pero","pestrost","petarda","petice","petrolej","pevnina","pexeso","pianista","piha","pijavice","pikle","piknik","pilina","pilnost","pilulka","pinzeta","pipeta","pisatel","pistole","pitevna","pivnice","pivovar","placenta","plakat","plamen","planeta","plastika","platit","plavidlo","plaz","plech","plemeno","plenta","ples","pletivo","plevel","plivat","plnit","plno","plocha","plodina","plomba","plout","pluk","plyn","pobavit","pobyt","pochod","pocit","poctivec","podat","podcenit","podepsat","podhled","podivit","podklad","podmanit","podnik","podoba","podpora","podraz","podstata","podvod","podzim","poezie","pohanka","pohnutka","pohovor","pohroma","pohyb","pointa","pojistka","pojmout","pokazit","pokles","pokoj","pokrok","pokuta","pokyn","poledne","polibek","polknout","poloha","polynom","pomalu","pominout","pomlka","pomoc","pomsta","pomyslet","ponechat","ponorka","ponurost","popadat","popel","popisek","poplach","poprosit","popsat","popud","poradce","porce","porod","porucha","poryv","posadit","posed","posila","poskok","poslanec","posoudit","pospolu","postava","posudek","posyp","potah","potkan","potlesk","potomek","potrava","potupa","potvora","poukaz","pouto","pouzdro","povaha","povidla","povlak","povoz","povrch","povstat","povyk","povzdech","pozdrav","pozemek","poznatek","pozor","pozvat","pracovat","prahory","praktika","prales","praotec","praporek","prase","pravda","princip","prkno","probudit","procento","prodej","profese","prohra","projekt","prolomit","promile","pronikat","propad","prorok","prosba","proton","proutek","provaz","prskavka","prsten","prudkost","prut","prvek","prvohory","psanec","psovod","pstruh","ptactvo","puberta","puch","pudl","pukavec","puklina","pukrle","pult","pumpa","punc","pupen","pusa","pusinka","pustina","putovat","putyka","pyramida","pysk","pytel","racek","rachot","radiace","radnice","radon","raft","ragby","raketa","rakovina","rameno","rampouch","rande","rarach","rarita","rasovna","rastr","ratolest","razance","razidlo","reagovat","reakce","recept","redaktor","referent","reflex","rejnok","reklama","rekord","rekrut","rektor","reputace","revize","revma","revolver","rezerva","riskovat","riziko","robotika","rodokmen","rohovka","rokle","rokoko","romaneto","ropovod","ropucha","rorejs","rosol","rostlina","rotmistr","rotoped","rotunda","roubenka","roucho","roup","roura","rovina","rovnice","rozbor","rozchod","rozdat","rozeznat","rozhodce","rozinka","rozjezd","rozkaz","rozloha","rozmar","rozpad","rozruch","rozsah","roztok","rozum","rozvod","rubrika","ruchadlo","rukavice","rukopis","ryba","rybolov","rychlost","rydlo","rypadlo","rytina","ryzost","sadista","sahat","sako","samec","samizdat","samota","sanitka","sardinka","sasanka","satelit","sazba","sazenice","sbor","schovat","sebranka","secese","sedadlo","sediment","sedlo","sehnat","sejmout","sekera","sekta","sekunda","sekvoje","semeno","seno","servis","sesadit","seshora","seskok","seslat","sestra","sesuv","sesypat","setba","setina","setkat","setnout","setrvat","sever","seznam","shoda","shrnout","sifon","silnice","sirka","sirotek","sirup","situace","skafandr","skalisko","skanzen","skaut","skeptik","skica","skladba","sklenice","sklo","skluz","skoba","skokan","skoro","skripta","skrz","skupina","skvost","skvrna","slabika","sladidlo","slanina","slast","slavnost","sledovat","slepec","sleva","slezina","slib","slina","sliznice","slon","sloupek","slovo","sluch","sluha","slunce","slupka","slza","smaragd","smetana","smilstvo","smlouva","smog","smrad","smrk","smrtka","smutek","smysl","snad","snaha","snob","sobota","socha","sodovka","sokol","sopka","sotva","souboj","soucit","soudce","souhlas","soulad","soumrak","souprava","soused","soutok","souviset","spalovna","spasitel","spis","splav","spodek","spojenec","spolu","sponzor","spornost","spousta","sprcha","spustit","sranda","sraz","srdce","srna","srnec","srovnat","srpen","srst","srub","stanice","starosta","statika","stavba","stehno","stezka","stodola","stolek","stopa","storno","stoupat","strach","stres","strhnout","strom","struna","studna","stupnice","stvol","styk","subjekt","subtropy","suchar","sudost","sukno","sundat","sunout","surikata","surovina","svah","svalstvo","svetr","svatba","svazek","svisle","svitek","svoboda","svodidlo","svorka","svrab","sykavka","sykot","synek","synovec","sypat","sypkost","syrovost","sysel","sytost","tabletka","tabule","tahoun","tajemno","tajfun","tajga","tajit","tajnost","taktika","tamhle","tampon","tancovat","tanec","tanker","tapeta","tavenina","tazatel","technika","tehdy","tekutina","telefon","temnota","tendence","tenista","tenor","teplota","tepna","teprve","terapie","termoska","textil","ticho","tiskopis","titulek","tkadlec","tkanina","tlapka","tleskat","tlukot","tlupa","tmel","toaleta","topinka","topol","torzo","touha","toulec","tradice","traktor","tramp","trasa","traverza","trefit","trest","trezor","trhavina","trhlina","trochu","trojice","troska","trouba","trpce","trpitel","trpkost","trubec","truchlit","truhlice","trus","trvat","tudy","tuhnout","tuhost","tundra","turista","turnaj","tuzemsko","tvaroh","tvorba","tvrdost","tvrz","tygr","tykev","ubohost","uboze","ubrat","ubrousek","ubrus","ubytovna","ucho","uctivost","udivit","uhradit","ujednat","ujistit","ujmout","ukazatel","uklidnit","uklonit","ukotvit","ukrojit","ulice","ulita","ulovit","umyvadlo","unavit","uniforma","uniknout","upadnout","uplatnit","uplynout","upoutat","upravit","uran","urazit","usednout","usilovat","usmrtit","usnadnit","usnout","usoudit","ustlat","ustrnout","utahovat","utkat","utlumit","utonout","utopenec","utrousit","uvalit","uvolnit","uvozovka","uzdravit","uzel","uzenina","uzlina","uznat","vagon","valcha","valoun","vana","vandal","vanilka","varan","varhany","varovat","vcelku","vchod","vdova","vedro","vegetace","vejce","velbloud","veletrh","velitel","velmoc","velryba","venkov","veranda","verze","veselka","veskrze","vesnice","vespodu","vesta","veterina","veverka","vibrace","vichr","videohra","vidina","vidle","vila","vinice","viset","vitalita","vize","vizitka","vjezd","vklad","vkus","vlajka","vlak","vlasec","vlevo","vlhkost","vliv","vlnovka","vloupat","vnucovat","vnuk","voda","vodivost","vodoznak","vodstvo","vojensky","vojna","vojsko","volant","volba","volit","volno","voskovka","vozidlo","vozovna","vpravo","vrabec","vracet","vrah","vrata","vrba","vrcholek","vrhat","vrstva","vrtule","vsadit","vstoupit","vstup","vtip","vybavit","vybrat","vychovat","vydat","vydra","vyfotit","vyhledat","vyhnout","vyhodit","vyhradit","vyhubit","vyjasnit","vyjet","vyjmout","vyklopit","vykonat","vylekat","vymazat","vymezit","vymizet","vymyslet","vynechat","vynikat","vynutit","vypadat","vyplatit","vypravit","vypustit","vyrazit","vyrovnat","vyrvat","vyslovit","vysoko","vystavit","vysunout","vysypat","vytasit","vytesat","vytratit","vyvinout","vyvolat","vyvrhel","vyzdobit","vyznat","vzadu","vzbudit","vzchopit","vzdor","vzduch","vzdychat","vzestup","vzhledem","vzkaz","vzlykat","vznik","vzorek","vzpoura","vztah","vztek","xylofon","zabrat","zabydlet","zachovat","zadarmo","zadusit","zafoukat","zahltit","zahodit","zahrada","zahynout","zajatec","zajet","zajistit","zaklepat","zakoupit","zalepit","zamezit","zamotat","zamyslet","zanechat","zanikat","zaplatit","zapojit","zapsat","zarazit","zastavit","zasunout","zatajit","zatemnit","zatknout","zaujmout","zavalit","zavelet","zavinit","zavolat","zavrtat","zazvonit","zbavit","zbrusu","zbudovat","zbytek","zdaleka","zdarma","zdatnost","zdivo","zdobit","zdroj","zdvih","zdymadlo","zelenina","zeman","zemina","zeptat","zezadu","zezdola","zhatit","zhltnout","zhluboka","zhotovit","zhruba","zima","zimnice","zjemnit","zklamat","zkoumat","zkratka","zkumavka","zlato","zlehka","zloba","zlom","zlost","zlozvyk","zmapovat","zmar","zmatek","zmije","zmizet","zmocnit","zmodrat","zmrzlina","zmutovat","znak","znalost","znamenat","znovu","zobrazit","zotavit","zoubek","zoufale","zplodit","zpomalit","zprava","zprostit","zprudka","zprvu","zrada","zranit","zrcadlo","zrnitost","zrno","zrovna","zrychlit","zrzavost","zticha","ztratit","zubovina","zubr","zvednout","zvenku","zvesela","zvon","zvrat","zvukovod","zvyk"]');
const require$$1 = /* @__PURE__ */ JSON.parse('["的","一","是","在","不","了","有","和","人","这","中","大","为","上","个","国","我","以","要","他","时","来","用","们","生","到","作","地","于","出","就","分","对","成","会","可","主","发","年","动","同","工","也","能","下","过","子","说","产","种","面","而","方","后","多","定","行","学","法","所","民","得","经","十","三","之","进","着","等","部","度","家","电","力","里","如","水","化","高","自","二","理","起","小","物","现","实","加","量","都","两","体","制","机","当","使","点","从","业","本","去","把","性","好","应","开","它","合","还","因","由","其","些","然","前","外","天","政","四","日","那","社","义","事","平","形","相","全","表","间","样","与","关","各","重","新","线","内","数","正","心","反","你","明","看","原","又","么","利","比","或","但","质","气","第","向","道","命","此","变","条","只","没","结","解","问","意","建","月","公","无","系","军","很","情","者","最","立","代","想","已","通","并","提","直","题","党","程","展","五","果","料","象","员","革","位","入","常","文","总","次","品","式","活","设","及","管","特","件","长","求","老","头","基","资","边","流","路","级","少","图","山","统","接","知","较","将","组","见","计","别","她","手","角","期","根","论","运","农","指","几","九","区","强","放","决","西","被","干","做","必","战","先","回","则","任","取","据","处","队","南","给","色","光","门","即","保","治","北","造","百","规","热","领","七","海","口","东","导","器","压","志","世","金","增","争","济","阶","油","思","术","极","交","受","联","什","认","六","共","权","收","证","改","清","美","再","采","转","更","单","风","切","打","白","教","速","花","带","安","场","身","车","例","真","务","具","万","每","目","至","达","走","积","示","议","声","报","斗","完","类","八","离","华","名","确","才","科","张","信","马","节","话","米","整","空","元","况","今","集","温","传","土","许","步","群","广","石","记","需","段","研","界","拉","林","律","叫","且","究","观","越","织","装","影","算","低","持","音","众","书","布","复","容","儿","须","际","商","非","验","连","断","深","难","近","矿","千","周","委","素","技","备","半","办","青","省","列","习","响","约","支","般","史","感","劳","便","团","往","酸","历","市","克","何","除","消","构","府","称","太","准","精","值","号","率","族","维","划","选","标","写","存","候","毛","亲","快","效","斯","院","查","江","型","眼","王","按","格","养","易","置","派","层","片","始","却","专","状","育","厂","京","识","适","属","圆","包","火","住","调","满","县","局","照","参","红","细","引","听","该","铁","价","严","首","底","液","官","德","随","病","苏","失","尔","死","讲","配","女","黄","推","显","谈","罪","神","艺","呢","席","含","企","望","密","批","营","项","防","举","球","英","氧","势","告","李","台","落","木","帮","轮","破","亚","师","围","注","远","字","材","排","供","河","态","封","另","施","减","树","溶","怎","止","案","言","士","均","武","固","叶","鱼","波","视","仅","费","紧","爱","左","章","早","朝","害","续","轻","服","试","食","充","兵","源","判","护","司","足","某","练","差","致","板","田","降","黑","犯","负","击","范","继","兴","似","余","坚","曲","输","修","故","城","夫","够","送","笔","船","占","右","财","吃","富","春","职","觉","汉","画","功","巴","跟","虽","杂","飞","检","吸","助","升","阳","互","初","创","抗","考","投","坏","策","古","径","换","未","跑","留","钢","曾","端","责","站","简","述","钱","副","尽","帝","射","草","冲","承","独","令","限","阿","宣","环","双","请","超","微","让","控","州","良","轴","找","否","纪","益","依","优","顶","础","载","倒","房","突","坐","粉","敌","略","客","袁","冷","胜","绝","析","块","剂","测","丝","协","诉","念","陈","仍","罗","盐","友","洋","错","苦","夜","刑","移","频","逐","靠","混","母","短","皮","终","聚","汽","村","云","哪","既","距","卫","停","烈","央","察","烧","迅","境","若","印","洲","刻","括","激","孔","搞","甚","室","待","核","校","散","侵","吧","甲","游","久","菜","味","旧","模","湖","货","损","预","阻","毫","普","稳","乙","妈","植","息","扩","银","语","挥","酒","守","拿","序","纸","医","缺","雨","吗","针","刘","啊","急","唱","误","训","愿","审","附","获","茶","鲜","粮","斤","孩","脱","硫","肥","善","龙","演","父","渐","血","欢","械","掌","歌","沙","刚","攻","谓","盾","讨","晚","粒","乱","燃","矛","乎","杀","药","宁","鲁","贵","钟","煤","读","班","伯","香","介","迫","句","丰","培","握","兰","担","弦","蛋","沉","假","穿","执","答","乐","谁","顺","烟","缩","征","脸","喜","松","脚","困","异","免","背","星","福","买","染","井","概","慢","怕","磁","倍","祖","皇","促","静","补","评","翻","肉","践","尼","衣","宽","扬","棉","希","伤","操","垂","秋","宜","氢","套","督","振","架","亮","末","宪","庆","编","牛","触","映","雷","销","诗","座","居","抓","裂","胞","呼","娘","景","威","绿","晶","厚","盟","衡","鸡","孙","延","危","胶","屋","乡","临","陆","顾","掉","呀","灯","岁","措","束","耐","剧","玉","赵","跳","哥","季","课","凯","胡","额","款","绍","卷","齐","伟","蒸","殖","永","宗","苗","川","炉","岩","弱","零","杨","奏","沿","露","杆","探","滑","镇","饭","浓","航","怀","赶","库","夺","伊","灵","税","途","灭","赛","归","召","鼓","播","盘","裁","险","康","唯","录","菌","纯","借","糖","盖","横","符","私","努","堂","域","枪","润","幅","哈","竟","熟","虫","泽","脑","壤","碳","欧","遍","侧","寨","敢","彻","虑","斜","薄","庭","纳","弹","饲","伸","折","麦","湿","暗","荷","瓦","塞","床","筑","恶","户","访","塔","奇","透","梁","刀","旋","迹","卡","氯","遇","份","毒","泥","退","洗","摆","灰","彩","卖","耗","夏","择","忙","铜","献","硬","予","繁","圈","雪","函","亦","抽","篇","阵","阴","丁","尺","追","堆","雄","迎","泛","爸","楼","避","谋","吨","野","猪","旗","累","偏","典","馆","索","秦","脂","潮","爷","豆","忽","托","惊","塑","遗","愈","朱","替","纤","粗","倾","尚","痛","楚","谢","奋","购","磨","君","池","旁","碎","骨","监","捕","弟","暴","割","贯","殊","释","词","亡","壁","顿","宝","午","尘","闻","揭","炮","残","冬","桥","妇","警","综","招","吴","付","浮","遭","徐","您","摇","谷","赞","箱","隔","订","男","吹","园","纷","唐","败","宋","玻","巨","耕","坦","荣","闭","湾","键","凡","驻","锅","救","恩","剥","凝","碱","齿","截","炼","麻","纺","禁","废","盛","版","缓","净","睛","昌","婚","涉","筒","嘴","插","岸","朗","庄","街","藏","姑","贸","腐","奴","啦","惯","乘","伙","恢","匀","纱","扎","辩","耳","彪","臣","亿","璃","抵","脉","秀","萨","俄","网","舞","店","喷","纵","寸","汗","挂","洪","贺","闪","柬","爆","烯","津","稻","墙","软","勇","像","滚","厘","蒙","芳","肯","坡","柱","荡","腿","仪","旅","尾","轧","冰","贡","登","黎","削","钻","勒","逃","障","氨","郭","峰","币","港","伏","轨","亩","毕","擦","莫","刺","浪","秘","援","株","健","售","股","岛","甘","泡","睡","童","铸","汤","阀","休","汇","舍","牧","绕","炸","哲","磷","绩","朋","淡","尖","启","陷","柴","呈","徒","颜","泪","稍","忘","泵","蓝","拖","洞","授","镜","辛","壮","锋","贫","虚","弯","摩","泰","幼","廷","尊","窗","纲","弄","隶","疑","氏","宫","姐","震","瑞","怪","尤","琴","循","描","膜","违","夹","腰","缘","珠","穷","森","枝","竹","沟","催","绳","忆","邦","剩","幸","浆","栏","拥","牙","贮","礼","滤","钠","纹","罢","拍","咱","喊","袖","埃","勤","罚","焦","潜","伍","墨","欲","缝","姓","刊","饱","仿","奖","铝","鬼","丽","跨","默","挖","链","扫","喝","袋","炭","污","幕","诸","弧","励","梅","奶","洁","灾","舟","鉴","苯","讼","抱","毁","懂","寒","智","埔","寄","届","跃","渡","挑","丹","艰","贝","碰","拔","爹","戴","码","梦","芽","熔","赤","渔","哭","敬","颗","奔","铅","仲","虎","稀","妹","乏","珍","申","桌","遵","允","隆","螺","仓","魏","锐","晓","氮","兼","隐","碍","赫","拨","忠","肃","缸","牵","抢","博","巧","壳","兄","杜","讯","诚","碧","祥","柯","页","巡","矩","悲","灌","龄","伦","票","寻","桂","铺","圣","恐","恰","郑","趣","抬","荒","腾","贴","柔","滴","猛","阔","辆","妻","填","撤","储","签","闹","扰","紫","砂","递","戏","吊","陶","伐","喂","疗","瓶","婆","抚","臂","摸","忍","虾","蜡","邻","胸","巩","挤","偶","弃","槽","劲","乳","邓","吉","仁","烂","砖","租","乌","舰","伴","瓜","浅","丙","暂","燥","橡","柳","迷","暖","牌","秧","胆","详","簧","踏","瓷","谱","呆","宾","糊","洛","辉","愤","竞","隙","怒","粘","乃","绪","肩","籍","敏","涂","熙","皆","侦","悬","掘","享","纠","醒","狂","锁","淀","恨","牲","霸","爬","赏","逆","玩","陵","祝","秒","浙","貌","役","彼","悉","鸭","趋","凤","晨","畜","辈","秩","卵","署","梯","炎","滩","棋","驱","筛","峡","冒","啥","寿","译","浸","泉","帽","迟","硅","疆","贷","漏","稿","冠","嫩","胁","芯","牢","叛","蚀","奥","鸣","岭","羊","凭","串","塘","绘","酵","融","盆","锡","庙","筹","冻","辅","摄","袭","筋","拒","僚","旱","钾","鸟","漆","沈","眉","疏","添","棒","穗","硝","韩","逼","扭","侨","凉","挺","碗","栽","炒","杯","患","馏","劝","豪","辽","勃","鸿","旦","吏","拜","狗","埋","辊","掩","饮","搬","骂","辞","勾","扣","估","蒋","绒","雾","丈","朵","姆","拟","宇","辑","陕","雕","偿","蓄","崇","剪","倡","厅","咬","驶","薯","刷","斥","番","赋","奉","佛","浇","漫","曼","扇","钙","桃","扶","仔","返","俗","亏","腔","鞋","棱","覆","框","悄","叔","撞","骗","勘","旺","沸","孤","吐","孟","渠","屈","疾","妙","惜","仰","狠","胀","谐","抛","霉","桑","岗","嘛","衰","盗","渗","脏","赖","涌","甜","曹","阅","肌","哩","厉","烃","纬","毅","昨","伪","症","煮","叹","钉","搭","茎","笼","酷","偷","弓","锥","恒","杰","坑","鼻","翼","纶","叙","狱","逮","罐","络","棚","抑","膨","蔬","寺","骤","穆","冶","枯","册","尸","凸","绅","坯","牺","焰","轰","欣","晋","瘦","御","锭","锦","丧","旬","锻","垄","搜","扑","邀","亭","酯","迈","舒","脆","酶","闲","忧","酚","顽","羽","涨","卸","仗","陪","辟","惩","杭","姚","肚","捉","飘","漂","昆","欺","吾","郎","烷","汁","呵","饰","萧","雅","邮","迁","燕","撒","姻","赴","宴","烦","债","帐","斑","铃","旨","醇","董","饼","雏","姿","拌","傅","腹","妥","揉","贤","拆","歪","葡","胺","丢","浩","徽","昂","垫","挡","览","贪","慰","缴","汪","慌","冯","诺","姜","谊","凶","劣","诬","耀","昏","躺","盈","骑","乔","溪","丛","卢","抹","闷","咨","刮","驾","缆","悟","摘","铒","掷","颇","幻","柄","惠","惨","佳","仇","腊","窝","涤","剑","瞧","堡","泼","葱","罩","霍","捞","胎","苍","滨","俩","捅","湘","砍","霞","邵","萄","疯","淮","遂","熊","粪","烘","宿","档","戈","驳","嫂","裕","徙","箭","捐","肠","撑","晒","辨","殿","莲","摊","搅","酱","屏","疫","哀","蔡","堵","沫","皱","畅","叠","阁","莱","敲","辖","钩","痕","坝","巷","饿","祸","丘","玄","溜","曰","逻","彭","尝","卿","妨","艇","吞","韦","怨","矮","歇"]');
const require$$2 = /* @__PURE__ */ JSON.parse('["的","一","是","在","不","了","有","和","人","這","中","大","為","上","個","國","我","以","要","他","時","來","用","們","生","到","作","地","於","出","就","分","對","成","會","可","主","發","年","動","同","工","也","能","下","過","子","說","產","種","面","而","方","後","多","定","行","學","法","所","民","得","經","十","三","之","進","著","等","部","度","家","電","力","裡","如","水","化","高","自","二","理","起","小","物","現","實","加","量","都","兩","體","制","機","當","使","點","從","業","本","去","把","性","好","應","開","它","合","還","因","由","其","些","然","前","外","天","政","四","日","那","社","義","事","平","形","相","全","表","間","樣","與","關","各","重","新","線","內","數","正","心","反","你","明","看","原","又","麼","利","比","或","但","質","氣","第","向","道","命","此","變","條","只","沒","結","解","問","意","建","月","公","無","系","軍","很","情","者","最","立","代","想","已","通","並","提","直","題","黨","程","展","五","果","料","象","員","革","位","入","常","文","總","次","品","式","活","設","及","管","特","件","長","求","老","頭","基","資","邊","流","路","級","少","圖","山","統","接","知","較","將","組","見","計","別","她","手","角","期","根","論","運","農","指","幾","九","區","強","放","決","西","被","幹","做","必","戰","先","回","則","任","取","據","處","隊","南","給","色","光","門","即","保","治","北","造","百","規","熱","領","七","海","口","東","導","器","壓","志","世","金","增","爭","濟","階","油","思","術","極","交","受","聯","什","認","六","共","權","收","證","改","清","美","再","採","轉","更","單","風","切","打","白","教","速","花","帶","安","場","身","車","例","真","務","具","萬","每","目","至","達","走","積","示","議","聲","報","鬥","完","類","八","離","華","名","確","才","科","張","信","馬","節","話","米","整","空","元","況","今","集","溫","傳","土","許","步","群","廣","石","記","需","段","研","界","拉","林","律","叫","且","究","觀","越","織","裝","影","算","低","持","音","眾","書","布","复","容","兒","須","際","商","非","驗","連","斷","深","難","近","礦","千","週","委","素","技","備","半","辦","青","省","列","習","響","約","支","般","史","感","勞","便","團","往","酸","歷","市","克","何","除","消","構","府","稱","太","準","精","值","號","率","族","維","劃","選","標","寫","存","候","毛","親","快","效","斯","院","查","江","型","眼","王","按","格","養","易","置","派","層","片","始","卻","專","狀","育","廠","京","識","適","屬","圓","包","火","住","調","滿","縣","局","照","參","紅","細","引","聽","該","鐵","價","嚴","首","底","液","官","德","隨","病","蘇","失","爾","死","講","配","女","黃","推","顯","談","罪","神","藝","呢","席","含","企","望","密","批","營","項","防","舉","球","英","氧","勢","告","李","台","落","木","幫","輪","破","亞","師","圍","注","遠","字","材","排","供","河","態","封","另","施","減","樹","溶","怎","止","案","言","士","均","武","固","葉","魚","波","視","僅","費","緊","愛","左","章","早","朝","害","續","輕","服","試","食","充","兵","源","判","護","司","足","某","練","差","致","板","田","降","黑","犯","負","擊","范","繼","興","似","餘","堅","曲","輸","修","故","城","夫","夠","送","筆","船","佔","右","財","吃","富","春","職","覺","漢","畫","功","巴","跟","雖","雜","飛","檢","吸","助","昇","陽","互","初","創","抗","考","投","壞","策","古","徑","換","未","跑","留","鋼","曾","端","責","站","簡","述","錢","副","盡","帝","射","草","衝","承","獨","令","限","阿","宣","環","雙","請","超","微","讓","控","州","良","軸","找","否","紀","益","依","優","頂","礎","載","倒","房","突","坐","粉","敵","略","客","袁","冷","勝","絕","析","塊","劑","測","絲","協","訴","念","陳","仍","羅","鹽","友","洋","錯","苦","夜","刑","移","頻","逐","靠","混","母","短","皮","終","聚","汽","村","雲","哪","既","距","衛","停","烈","央","察","燒","迅","境","若","印","洲","刻","括","激","孔","搞","甚","室","待","核","校","散","侵","吧","甲","遊","久","菜","味","舊","模","湖","貨","損","預","阻","毫","普","穩","乙","媽","植","息","擴","銀","語","揮","酒","守","拿","序","紙","醫","缺","雨","嗎","針","劉","啊","急","唱","誤","訓","願","審","附","獲","茶","鮮","糧","斤","孩","脫","硫","肥","善","龍","演","父","漸","血","歡","械","掌","歌","沙","剛","攻","謂","盾","討","晚","粒","亂","燃","矛","乎","殺","藥","寧","魯","貴","鐘","煤","讀","班","伯","香","介","迫","句","豐","培","握","蘭","擔","弦","蛋","沉","假","穿","執","答","樂","誰","順","煙","縮","徵","臉","喜","松","腳","困","異","免","背","星","福","買","染","井","概","慢","怕","磁","倍","祖","皇","促","靜","補","評","翻","肉","踐","尼","衣","寬","揚","棉","希","傷","操","垂","秋","宜","氫","套","督","振","架","亮","末","憲","慶","編","牛","觸","映","雷","銷","詩","座","居","抓","裂","胞","呼","娘","景","威","綠","晶","厚","盟","衡","雞","孫","延","危","膠","屋","鄉","臨","陸","顧","掉","呀","燈","歲","措","束","耐","劇","玉","趙","跳","哥","季","課","凱","胡","額","款","紹","卷","齊","偉","蒸","殖","永","宗","苗","川","爐","岩","弱","零","楊","奏","沿","露","桿","探","滑","鎮","飯","濃","航","懷","趕","庫","奪","伊","靈","稅","途","滅","賽","歸","召","鼓","播","盤","裁","險","康","唯","錄","菌","純","借","糖","蓋","橫","符","私","努","堂","域","槍","潤","幅","哈","竟","熟","蟲","澤","腦","壤","碳","歐","遍","側","寨","敢","徹","慮","斜","薄","庭","納","彈","飼","伸","折","麥","濕","暗","荷","瓦","塞","床","築","惡","戶","訪","塔","奇","透","梁","刀","旋","跡","卡","氯","遇","份","毒","泥","退","洗","擺","灰","彩","賣","耗","夏","擇","忙","銅","獻","硬","予","繁","圈","雪","函","亦","抽","篇","陣","陰","丁","尺","追","堆","雄","迎","泛","爸","樓","避","謀","噸","野","豬","旗","累","偏","典","館","索","秦","脂","潮","爺","豆","忽","托","驚","塑","遺","愈","朱","替","纖","粗","傾","尚","痛","楚","謝","奮","購","磨","君","池","旁","碎","骨","監","捕","弟","暴","割","貫","殊","釋","詞","亡","壁","頓","寶","午","塵","聞","揭","炮","殘","冬","橋","婦","警","綜","招","吳","付","浮","遭","徐","您","搖","谷","贊","箱","隔","訂","男","吹","園","紛","唐","敗","宋","玻","巨","耕","坦","榮","閉","灣","鍵","凡","駐","鍋","救","恩","剝","凝","鹼","齒","截","煉","麻","紡","禁","廢","盛","版","緩","淨","睛","昌","婚","涉","筒","嘴","插","岸","朗","莊","街","藏","姑","貿","腐","奴","啦","慣","乘","夥","恢","勻","紗","扎","辯","耳","彪","臣","億","璃","抵","脈","秀","薩","俄","網","舞","店","噴","縱","寸","汗","掛","洪","賀","閃","柬","爆","烯","津","稻","牆","軟","勇","像","滾","厘","蒙","芳","肯","坡","柱","盪","腿","儀","旅","尾","軋","冰","貢","登","黎","削","鑽","勒","逃","障","氨","郭","峰","幣","港","伏","軌","畝","畢","擦","莫","刺","浪","秘","援","株","健","售","股","島","甘","泡","睡","童","鑄","湯","閥","休","匯","舍","牧","繞","炸","哲","磷","績","朋","淡","尖","啟","陷","柴","呈","徒","顏","淚","稍","忘","泵","藍","拖","洞","授","鏡","辛","壯","鋒","貧","虛","彎","摩","泰","幼","廷","尊","窗","綱","弄","隸","疑","氏","宮","姐","震","瑞","怪","尤","琴","循","描","膜","違","夾","腰","緣","珠","窮","森","枝","竹","溝","催","繩","憶","邦","剩","幸","漿","欄","擁","牙","貯","禮","濾","鈉","紋","罷","拍","咱","喊","袖","埃","勤","罰","焦","潛","伍","墨","欲","縫","姓","刊","飽","仿","獎","鋁","鬼","麗","跨","默","挖","鏈","掃","喝","袋","炭","污","幕","諸","弧","勵","梅","奶","潔","災","舟","鑑","苯","訟","抱","毀","懂","寒","智","埔","寄","屆","躍","渡","挑","丹","艱","貝","碰","拔","爹","戴","碼","夢","芽","熔","赤","漁","哭","敬","顆","奔","鉛","仲","虎","稀","妹","乏","珍","申","桌","遵","允","隆","螺","倉","魏","銳","曉","氮","兼","隱","礙","赫","撥","忠","肅","缸","牽","搶","博","巧","殼","兄","杜","訊","誠","碧","祥","柯","頁","巡","矩","悲","灌","齡","倫","票","尋","桂","鋪","聖","恐","恰","鄭","趣","抬","荒","騰","貼","柔","滴","猛","闊","輛","妻","填","撤","儲","簽","鬧","擾","紫","砂","遞","戲","吊","陶","伐","餵","療","瓶","婆","撫","臂","摸","忍","蝦","蠟","鄰","胸","鞏","擠","偶","棄","槽","勁","乳","鄧","吉","仁","爛","磚","租","烏","艦","伴","瓜","淺","丙","暫","燥","橡","柳","迷","暖","牌","秧","膽","詳","簧","踏","瓷","譜","呆","賓","糊","洛","輝","憤","競","隙","怒","粘","乃","緒","肩","籍","敏","塗","熙","皆","偵","懸","掘","享","糾","醒","狂","鎖","淀","恨","牲","霸","爬","賞","逆","玩","陵","祝","秒","浙","貌","役","彼","悉","鴨","趨","鳳","晨","畜","輩","秩","卵","署","梯","炎","灘","棋","驅","篩","峽","冒","啥","壽","譯","浸","泉","帽","遲","矽","疆","貸","漏","稿","冠","嫩","脅","芯","牢","叛","蝕","奧","鳴","嶺","羊","憑","串","塘","繪","酵","融","盆","錫","廟","籌","凍","輔","攝","襲","筋","拒","僚","旱","鉀","鳥","漆","沈","眉","疏","添","棒","穗","硝","韓","逼","扭","僑","涼","挺","碗","栽","炒","杯","患","餾","勸","豪","遼","勃","鴻","旦","吏","拜","狗","埋","輥","掩","飲","搬","罵","辭","勾","扣","估","蔣","絨","霧","丈","朵","姆","擬","宇","輯","陝","雕","償","蓄","崇","剪","倡","廳","咬","駛","薯","刷","斥","番","賦","奉","佛","澆","漫","曼","扇","鈣","桃","扶","仔","返","俗","虧","腔","鞋","棱","覆","框","悄","叔","撞","騙","勘","旺","沸","孤","吐","孟","渠","屈","疾","妙","惜","仰","狠","脹","諧","拋","黴","桑","崗","嘛","衰","盜","滲","臟","賴","湧","甜","曹","閱","肌","哩","厲","烴","緯","毅","昨","偽","症","煮","嘆","釘","搭","莖","籠","酷","偷","弓","錐","恆","傑","坑","鼻","翼","綸","敘","獄","逮","罐","絡","棚","抑","膨","蔬","寺","驟","穆","冶","枯","冊","屍","凸","紳","坯","犧","焰","轟","欣","晉","瘦","禦","錠","錦","喪","旬","鍛","壟","搜","撲","邀","亭","酯","邁","舒","脆","酶","閒","憂","酚","頑","羽","漲","卸","仗","陪","闢","懲","杭","姚","肚","捉","飄","漂","昆","欺","吾","郎","烷","汁","呵","飾","蕭","雅","郵","遷","燕","撒","姻","赴","宴","煩","債","帳","斑","鈴","旨","醇","董","餅","雛","姿","拌","傅","腹","妥","揉","賢","拆","歪","葡","胺","丟","浩","徽","昂","墊","擋","覽","貪","慰","繳","汪","慌","馮","諾","姜","誼","兇","劣","誣","耀","昏","躺","盈","騎","喬","溪","叢","盧","抹","悶","諮","刮","駕","纜","悟","摘","鉺","擲","頗","幻","柄","惠","慘","佳","仇","臘","窩","滌","劍","瞧","堡","潑","蔥","罩","霍","撈","胎","蒼","濱","倆","捅","湘","砍","霞","邵","萄","瘋","淮","遂","熊","糞","烘","宿","檔","戈","駁","嫂","裕","徙","箭","捐","腸","撐","曬","辨","殿","蓮","攤","攪","醬","屏","疫","哀","蔡","堵","沫","皺","暢","疊","閣","萊","敲","轄","鉤","痕","壩","巷","餓","禍","丘","玄","溜","曰","邏","彭","嘗","卿","妨","艇","吞","韋","怨","矮","歇"]');
const require$$3 = /* @__PURE__ */ JSON.parse('["가격","가끔","가난","가능","가득","가르침","가뭄","가방","가상","가슴","가운데","가을","가이드","가입","가장","가정","가족","가죽","각오","각자","간격","간부","간섭","간장","간접","간판","갈등","갈비","갈색","갈증","감각","감기","감소","감수성","감자","감정","갑자기","강남","강당","강도","강력히","강변","강북","강사","강수량","강아지","강원도","강의","강제","강조","같이","개구리","개나리","개방","개별","개선","개성","개인","객관적","거실","거액","거울","거짓","거품","걱정","건강","건물","건설","건조","건축","걸음","검사","검토","게시판","게임","겨울","견해","결과","결국","결론","결석","결승","결심","결정","결혼","경계","경고","경기","경력","경복궁","경비","경상도","경영","경우","경쟁","경제","경주","경찰","경치","경향","경험","계곡","계단","계란","계산","계속","계약","계절","계층","계획","고객","고구려","고궁","고급","고등학생","고무신","고민","고양이","고장","고전","고집","고춧가루","고통","고향","곡식","골목","골짜기","골프","공간","공개","공격","공군","공급","공기","공동","공무원","공부","공사","공식","공업","공연","공원","공장","공짜","공책","공통","공포","공항","공휴일","과목","과일","과장","과정","과학","관객","관계","관광","관념","관람","관련","관리","관습","관심","관점","관찰","광경","광고","광장","광주","괴로움","굉장히","교과서","교문","교복","교실","교양","교육","교장","교직","교통","교환","교훈","구경","구름","구멍","구별","구분","구석","구성","구속","구역","구입","구청","구체적","국가","국기","국내","국립","국물","국민","국수","국어","국왕","국적","국제","국회","군대","군사","군인","궁극적","권리","권위","권투","귀국","귀신","규정","규칙","균형","그날","그냥","그늘","그러나","그룹","그릇","그림","그제서야","그토록","극복","극히","근거","근교","근래","근로","근무","근본","근원","근육","근처","글씨","글자","금강산","금고","금년","금메달","금액","금연","금요일","금지","긍정적","기간","기관","기념","기능","기독교","기둥","기록","기름","기법","기본","기분","기쁨","기숙사","기술","기억","기업","기온","기운","기원","기적","기준","기침","기혼","기획","긴급","긴장","길이","김밥","김치","김포공항","깍두기","깜빡","깨달음","깨소금","껍질","꼭대기","꽃잎","나들이","나란히","나머지","나물","나침반","나흘","낙엽","난방","날개","날씨","날짜","남녀","남대문","남매","남산","남자","남편","남학생","낭비","낱말","내년","내용","내일","냄비","냄새","냇물","냉동","냉면","냉방","냉장고","넥타이","넷째","노동","노란색","노력","노인","녹음","녹차","녹화","논리","논문","논쟁","놀이","농구","농담","농민","농부","농업","농장","농촌","높이","눈동자","눈물","눈썹","뉴욕","느낌","늑대","능동적","능력","다방","다양성","다음","다이어트","다행","단계","단골","단독","단맛","단순","단어","단위","단점","단체","단추","단편","단풍","달걀","달러","달력","달리","닭고기","담당","담배","담요","담임","답변","답장","당근","당분간","당연히","당장","대규모","대낮","대단히","대답","대도시","대략","대량","대륙","대문","대부분","대신","대응","대장","대전","대접","대중","대책","대출","대충","대통령","대학","대한민국","대합실","대형","덩어리","데이트","도대체","도덕","도둑","도망","도서관","도심","도움","도입","도자기","도저히","도전","도중","도착","독감","독립","독서","독일","독창적","동화책","뒷모습","뒷산","딸아이","마누라","마늘","마당","마라톤","마련","마무리","마사지","마약","마요네즈","마을","마음","마이크","마중","마지막","마찬가지","마찰","마흔","막걸리","막내","막상","만남","만두","만세","만약","만일","만점","만족","만화","많이","말기","말씀","말투","맘대로","망원경","매년","매달","매력","매번","매스컴","매일","매장","맥주","먹이","먼저","먼지","멀리","메일","며느리","며칠","면담","멸치","명단","명령","명예","명의","명절","명칭","명함","모금","모니터","모델","모든","모범","모습","모양","모임","모조리","모집","모퉁이","목걸이","목록","목사","목소리","목숨","목적","목표","몰래","몸매","몸무게","몸살","몸속","몸짓","몸통","몹시","무관심","무궁화","무더위","무덤","무릎","무슨","무엇","무역","무용","무조건","무지개","무척","문구","문득","문법","문서","문제","문학","문화","물가","물건","물결","물고기","물론","물리학","물음","물질","물체","미국","미디어","미사일","미술","미역","미용실","미움","미인","미팅","미혼","민간","민족","민주","믿음","밀가루","밀리미터","밑바닥","바가지","바구니","바나나","바늘","바닥","바닷가","바람","바이러스","바탕","박물관","박사","박수","반대","반드시","반말","반발","반성","반응","반장","반죽","반지","반찬","받침","발가락","발걸음","발견","발달","발레","발목","발바닥","발생","발음","발자국","발전","발톱","발표","밤하늘","밥그릇","밥맛","밥상","밥솥","방금","방면","방문","방바닥","방법","방송","방식","방안","방울","방지","방학","방해","방향","배경","배꼽","배달","배드민턴","백두산","백색","백성","백인","백제","백화점","버릇","버섯","버튼","번개","번역","번지","번호","벌금","벌레","벌써","범위","범인","범죄","법률","법원","법적","법칙","베이징","벨트","변경","변동","변명","변신","변호사","변화","별도","별명","별일","병실","병아리","병원","보관","보너스","보라색","보람","보름","보상","보안","보자기","보장","보전","보존","보통","보편적","보험","복도","복사","복숭아","복습","볶음","본격적","본래","본부","본사","본성","본인","본질","볼펜","봉사","봉지","봉투","부근","부끄러움","부담","부동산","부문","부분","부산","부상","부엌","부인","부작용","부장","부정","부족","부지런히","부친","부탁","부품","부회장","북부","북한","분노","분량","분리","분명","분석","분야","분위기","분필","분홍색","불고기","불과","불교","불꽃","불만","불법","불빛","불안","불이익","불행","브랜드","비극","비난","비닐","비둘기","비디오","비로소","비만","비명","비밀","비바람","비빔밥","비상","비용","비율","비중","비타민","비판","빌딩","빗물","빗방울","빗줄기","빛깔","빨간색","빨래","빨리","사건","사계절","사나이","사냥","사람","사랑","사립","사모님","사물","사방","사상","사생활","사설","사슴","사실","사업","사용","사월","사장","사전","사진","사촌","사춘기","사탕","사투리","사흘","산길","산부인과","산업","산책","살림","살인","살짝","삼계탕","삼국","삼십","삼월","삼촌","상관","상금","상대","상류","상반기","상상","상식","상업","상인","상자","상점","상처","상추","상태","상표","상품","상황","새벽","색깔","색연필","생각","생명","생물","생방송","생산","생선","생신","생일","생활","서랍","서른","서명","서민","서비스","서양","서울","서적","서점","서쪽","서클","석사","석유","선거","선물","선배","선생","선수","선원","선장","선전","선택","선풍기","설거지","설날","설렁탕","설명","설문","설사","설악산","설치","설탕","섭씨","성공","성당","성명","성별","성인","성장","성적","성질","성함","세금","세미나","세상","세월","세종대왕","세탁","센터","센티미터","셋째","소규모","소극적","소금","소나기","소년","소득","소망","소문","소설","소속","소아과","소용","소원","소음","소중히","소지품","소질","소풍","소형","속담","속도","속옷","손가락","손길","손녀","손님","손등","손목","손뼉","손실","손질","손톱","손해","솔직히","솜씨","송아지","송이","송편","쇠고기","쇼핑","수건","수년","수단","수돗물","수동적","수면","수명","수박","수상","수석","수술","수시로","수업","수염","수영","수입","수준","수집","수출","수컷","수필","수학","수험생","수화기","숙녀","숙소","숙제","순간","순서","순수","순식간","순위","숟가락","술병","술집","숫자","스님","스물","스스로","스승","스웨터","스위치","스케이트","스튜디오","스트레스","스포츠","슬쩍","슬픔","습관","습기","승객","승리","승부","승용차","승진","시각","시간","시골","시금치","시나리오","시댁","시리즈","시멘트","시민","시부모","시선","시설","시스템","시아버지","시어머니","시월","시인","시일","시작","시장","시절","시점","시중","시즌","시집","시청","시합","시험","식구","식기","식당","식량","식료품","식물","식빵","식사","식생활","식초","식탁","식품","신고","신규","신념","신문","신발","신비","신사","신세","신용","신제품","신청","신체","신화","실감","실내","실력","실례","실망","실수","실습","실시","실장","실정","실질적","실천","실체","실컷","실태","실패","실험","실현","심리","심부름","심사","심장","심정","심판","쌍둥이","씨름","씨앗","아가씨","아나운서","아드님","아들","아쉬움","아스팔트","아시아","아울러","아저씨","아줌마","아직","아침","아파트","아프리카","아픔","아홉","아흔","악기","악몽","악수","안개","안경","안과","안내","안녕","안동","안방","안부","안주","알루미늄","알코올","암시","암컷","압력","앞날","앞문","애인","애정","액수","앨범","야간","야단","야옹","약간","약국","약속","약수","약점","약품","약혼녀","양념","양력","양말","양배추","양주","양파","어둠","어려움","어른","어젯밤","어쨌든","어쩌다가","어쩐지","언니","언덕","언론","언어","얼굴","얼른","얼음","얼핏","엄마","업무","업종","업체","엉덩이","엉망","엉터리","엊그제","에너지","에어컨","엔진","여건","여고생","여관","여군","여권","여대생","여덟","여동생","여든","여론","여름","여섯","여성","여왕","여인","여전히","여직원","여학생","여행","역사","역시","역할","연결","연구","연극","연기","연락","연설","연세","연속","연습","연애","연예인","연인","연장","연주","연출","연필","연합","연휴","열기","열매","열쇠","열심히","열정","열차","열흘","염려","엽서","영국","영남","영상","영양","영역","영웅","영원히","영하","영향","영혼","영화","옆구리","옆방","옆집","예감","예금","예방","예산","예상","예선","예술","예습","예식장","예약","예전","예절","예정","예컨대","옛날","오늘","오락","오랫동안","오렌지","오로지","오른발","오븐","오십","오염","오월","오전","오직","오징어","오페라","오피스텔","오히려","옥상","옥수수","온갖","온라인","온몸","온종일","온통","올가을","올림픽","올해","옷차림","와이셔츠","와인","완성","완전","왕비","왕자","왜냐하면","왠지","외갓집","외국","외로움","외삼촌","외출","외침","외할머니","왼발","왼손","왼쪽","요금","요일","요즘","요청","용기","용서","용어","우산","우선","우승","우연히","우정","우체국","우편","운동","운명","운반","운전","운행","울산","울음","움직임","웃어른","웃음","워낙","원고","원래","원서","원숭이","원인","원장","원피스","월급","월드컵","월세","월요일","웨이터","위반","위법","위성","위원","위험","위협","윗사람","유난히","유럽","유명","유물","유산","유적","유치원","유학","유행","유형","육군","육상","육십","육체","은행","음력","음료","음반","음성","음식","음악","음주","의견","의논","의문","의복","의식","의심","의외로","의욕","의원","의학","이것","이곳","이념","이놈","이달","이대로","이동","이렇게","이력서","이론적","이름","이민","이발소","이별","이불","이빨","이상","이성","이슬","이야기","이용","이웃","이월","이윽고","이익","이전","이중","이튿날","이틀","이혼","인간","인격","인공","인구","인근","인기","인도","인류","인물","인생","인쇄","인연","인원","인재","인종","인천","인체","인터넷","인하","인형","일곱","일기","일단","일대","일등","일반","일본","일부","일상","일생","일손","일요일","일월","일정","일종","일주일","일찍","일체","일치","일행","일회용","임금","임무","입대","입력","입맛","입사","입술","입시","입원","입장","입학","자가용","자격","자극","자동","자랑","자부심","자식","자신","자연","자원","자율","자전거","자정","자존심","자판","작가","작년","작성","작업","작용","작은딸","작품","잔디","잔뜩","잔치","잘못","잠깐","잠수함","잠시","잠옷","잠자리","잡지","장관","장군","장기간","장래","장례","장르","장마","장면","장모","장미","장비","장사","장소","장식","장애인","장인","장점","장차","장학금","재능","재빨리","재산","재생","재작년","재정","재채기","재판","재학","재활용","저것","저고리","저곳","저녁","저런","저렇게","저번","저울","저절로","저축","적극","적당히","적성","적용","적응","전개","전공","전기","전달","전라도","전망","전문","전반","전부","전세","전시","전용","전자","전쟁","전주","전철","전체","전통","전혀","전후","절대","절망","절반","절약","절차","점검","점수","점심","점원","점점","점차","접근","접시","접촉","젓가락","정거장","정도","정류장","정리","정말","정면","정문","정반대","정보","정부","정비","정상","정성","정오","정원","정장","정지","정치","정확히","제공","제과점","제대로","제목","제발","제법","제삿날","제안","제일","제작","제주도","제출","제품","제한","조각","조건","조금","조깅","조명","조미료","조상","조선","조용히","조절","조정","조직","존댓말","존재","졸업","졸음","종교","종로","종류","종소리","종업원","종종","종합","좌석","죄인","주관적","주름","주말","주머니","주먹","주문","주민","주방","주변","주식","주인","주일","주장","주전자","주택","준비","줄거리","줄기","줄무늬","중간","중계방송","중국","중년","중단","중독","중반","중부","중세","중소기업","중순","중앙","중요","중학교","즉석","즉시","즐거움","증가","증거","증권","증상","증세","지각","지갑","지경","지극히","지금","지급","지능","지름길","지리산","지방","지붕","지식","지역","지우개","지원","지적","지점","지진","지출","직선","직업","직원","직장","진급","진동","진로","진료","진리","진짜","진찰","진출","진통","진행","질문","질병","질서","짐작","집단","집안","집중","짜증","찌꺼기","차남","차라리","차량","차림","차별","차선","차츰","착각","찬물","찬성","참가","참기름","참새","참석","참여","참외","참조","찻잔","창가","창고","창구","창문","창밖","창작","창조","채널","채점","책가방","책방","책상","책임","챔피언","처벌","처음","천국","천둥","천장","천재","천천히","철도","철저히","철학","첫날","첫째","청년","청바지","청소","청춘","체계","체력","체온","체육","체중","체험","초등학생","초반","초밥","초상화","초순","초여름","초원","초저녁","초점","초청","초콜릿","촛불","총각","총리","총장","촬영","최근","최상","최선","최신","최악","최종","추석","추억","추진","추천","추측","축구","축소","축제","축하","출근","출발","출산","출신","출연","출입","출장","출판","충격","충고","충돌","충분히","충청도","취업","취직","취향","치약","친구","친척","칠십","칠월","칠판","침대","침묵","침실","칫솔","칭찬","카메라","카운터","칼국수","캐릭터","캠퍼스","캠페인","커튼","컨디션","컬러","컴퓨터","코끼리","코미디","콘서트","콜라","콤플렉스","콩나물","쾌감","쿠데타","크림","큰길","큰딸","큰소리","큰아들","큰어머니","큰일","큰절","클래식","클럽","킬로","타입","타자기","탁구","탁자","탄생","태권도","태양","태풍","택시","탤런트","터널","터미널","테니스","테스트","테이블","텔레비전","토론","토마토","토요일","통계","통과","통로","통신","통역","통일","통장","통제","통증","통합","통화","퇴근","퇴원","퇴직금","튀김","트럭","특급","특별","특성","특수","특징","특히","튼튼히","티셔츠","파란색","파일","파출소","판결","판단","판매","판사","팔십","팔월","팝송","패션","팩스","팩시밀리","팬티","퍼센트","페인트","편견","편의","편지","편히","평가","평균","평생","평소","평양","평일","평화","포스터","포인트","포장","포함","표면","표정","표준","표현","품목","품질","풍경","풍속","풍습","프랑스","프린터","플라스틱","피곤","피망","피아노","필름","필수","필요","필자","필통","핑계","하느님","하늘","하드웨어","하룻밤","하반기","하숙집","하순","하여튼","하지만","하천","하품","하필","학과","학교","학급","학기","학년","학력","학번","학부모","학비","학생","학술","학습","학용품","학원","학위","학자","학점","한계","한글","한꺼번에","한낮","한눈","한동안","한때","한라산","한마디","한문","한번","한복","한식","한여름","한쪽","할머니","할아버지","할인","함께","함부로","합격","합리적","항공","항구","항상","항의","해결","해군","해답","해당","해물","해석","해설","해수욕장","해안","핵심","핸드백","햄버거","햇볕","햇살","행동","행복","행사","행운","행위","향기","향상","향수","허락","허용","헬기","현관","현금","현대","현상","현실","현장","현재","현지","혈액","협력","형부","형사","형수","형식","형제","형태","형편","혜택","호기심","호남","호랑이","호박","호텔","호흡","혹시","홀로","홈페이지","홍보","홍수","홍차","화면","화분","화살","화요일","화장","화학","확보","확인","확장","확정","환갑","환경","환영","환율","환자","활기","활동","활발히","활용","활짝","회견","회관","회복","회색","회원","회장","회전","횟수","횡단보도","효율적","후반","후춧가루","훈련","훨씬","휴식","휴일","흉내","흐름","흑백","흑인","흔적","흔히","흥미","흥분","희곡","희망","희생","흰색","힘껏"]');
const require$$4 = /* @__PURE__ */ JSON.parse('["abaisser","abandon","abdiquer","abeille","abolir","aborder","aboutir","aboyer","abrasif","abreuver","abriter","abroger","abrupt","absence","absolu","absurde","abusif","abyssal","académie","acajou","acarien","accabler","accepter","acclamer","accolade","accroche","accuser","acerbe","achat","acheter","aciduler","acier","acompte","acquérir","acronyme","acteur","actif","actuel","adepte","adéquat","adhésif","adjectif","adjuger","admettre","admirer","adopter","adorer","adoucir","adresse","adroit","adulte","adverbe","aérer","aéronef","affaire","affecter","affiche","affreux","affubler","agacer","agencer","agile","agiter","agrafer","agréable","agrume","aider","aiguille","ailier","aimable","aisance","ajouter","ajuster","alarmer","alchimie","alerte","algèbre","algue","aliéner","aliment","alléger","alliage","allouer","allumer","alourdir","alpaga","altesse","alvéole","amateur","ambigu","ambre","aménager","amertume","amidon","amiral","amorcer","amour","amovible","amphibie","ampleur","amusant","analyse","anaphore","anarchie","anatomie","ancien","anéantir","angle","angoisse","anguleux","animal","annexer","annonce","annuel","anodin","anomalie","anonyme","anormal","antenne","antidote","anxieux","apaiser","apéritif","aplanir","apologie","appareil","appeler","apporter","appuyer","aquarium","aqueduc","arbitre","arbuste","ardeur","ardoise","argent","arlequin","armature","armement","armoire","armure","arpenter","arracher","arriver","arroser","arsenic","artériel","article","aspect","asphalte","aspirer","assaut","asservir","assiette","associer","assurer","asticot","astre","astuce","atelier","atome","atrium","atroce","attaque","attentif","attirer","attraper","aubaine","auberge","audace","audible","augurer","aurore","automne","autruche","avaler","avancer","avarice","avenir","averse","aveugle","aviateur","avide","avion","aviser","avoine","avouer","avril","axial","axiome","badge","bafouer","bagage","baguette","baignade","balancer","balcon","baleine","balisage","bambin","bancaire","bandage","banlieue","bannière","banquier","barbier","baril","baron","barque","barrage","bassin","bastion","bataille","bateau","batterie","baudrier","bavarder","belette","bélier","belote","bénéfice","berceau","berger","berline","bermuda","besace","besogne","bétail","beurre","biberon","bicycle","bidule","bijou","bilan","bilingue","billard","binaire","biologie","biopsie","biotype","biscuit","bison","bistouri","bitume","bizarre","blafard","blague","blanchir","blessant","blinder","blond","bloquer","blouson","bobard","bobine","boire","boiser","bolide","bonbon","bondir","bonheur","bonifier","bonus","bordure","borne","botte","boucle","boueux","bougie","boulon","bouquin","bourse","boussole","boutique","boxeur","branche","brasier","brave","brebis","brèche","breuvage","bricoler","brigade","brillant","brioche","brique","brochure","broder","bronzer","brousse","broyeur","brume","brusque","brutal","bruyant","buffle","buisson","bulletin","bureau","burin","bustier","butiner","butoir","buvable","buvette","cabanon","cabine","cachette","cadeau","cadre","caféine","caillou","caisson","calculer","calepin","calibre","calmer","calomnie","calvaire","camarade","caméra","camion","campagne","canal","caneton","canon","cantine","canular","capable","caporal","caprice","capsule","capter","capuche","carabine","carbone","caresser","caribou","carnage","carotte","carreau","carton","cascade","casier","casque","cassure","causer","caution","cavalier","caverne","caviar","cédille","ceinture","céleste","cellule","cendrier","censurer","central","cercle","cérébral","cerise","cerner","cerveau","cesser","chagrin","chaise","chaleur","chambre","chance","chapitre","charbon","chasseur","chaton","chausson","chavirer","chemise","chenille","chéquier","chercher","cheval","chien","chiffre","chignon","chimère","chiot","chlorure","chocolat","choisir","chose","chouette","chrome","chute","cigare","cigogne","cimenter","cinéma","cintrer","circuler","cirer","cirque","citerne","citoyen","citron","civil","clairon","clameur","claquer","classe","clavier","client","cligner","climat","clivage","cloche","clonage","cloporte","cobalt","cobra","cocasse","cocotier","coder","codifier","coffre","cogner","cohésion","coiffer","coincer","colère","colibri","colline","colmater","colonel","combat","comédie","commande","compact","concert","conduire","confier","congeler","connoter","consonne","contact","convexe","copain","copie","corail","corbeau","cordage","corniche","corpus","correct","cortège","cosmique","costume","coton","coude","coupure","courage","couteau","couvrir","coyote","crabe","crainte","cravate","crayon","créature","créditer","crémeux","creuser","crevette","cribler","crier","cristal","critère","croire","croquer","crotale","crucial","cruel","crypter","cubique","cueillir","cuillère","cuisine","cuivre","culminer","cultiver","cumuler","cupide","curatif","curseur","cyanure","cycle","cylindre","cynique","daigner","damier","danger","danseur","dauphin","débattre","débiter","déborder","débrider","débutant","décaler","décembre","déchirer","décider","déclarer","décorer","décrire","décupler","dédale","déductif","déesse","défensif","défiler","défrayer","dégager","dégivrer","déglutir","dégrafer","déjeuner","délice","déloger","demander","demeurer","démolir","dénicher","dénouer","dentelle","dénuder","départ","dépenser","déphaser","déplacer","déposer","déranger","dérober","désastre","descente","désert","désigner","désobéir","dessiner","destrier","détacher","détester","détourer","détresse","devancer","devenir","deviner","devoir","diable","dialogue","diamant","dicter","différer","digérer","digital","digne","diluer","dimanche","diminuer","dioxyde","directif","diriger","discuter","disposer","dissiper","distance","divertir","diviser","docile","docteur","dogme","doigt","domaine","domicile","dompter","donateur","donjon","donner","dopamine","dortoir","dorure","dosage","doseur","dossier","dotation","douanier","double","douceur","douter","doyen","dragon","draper","dresser","dribbler","droiture","duperie","duplexe","durable","durcir","dynastie","éblouir","écarter","écharpe","échelle","éclairer","éclipse","éclore","écluse","école","économie","écorce","écouter","écraser","écrémer","écrivain","écrou","écume","écureuil","édifier","éduquer","effacer","effectif","effigie","effort","effrayer","effusion","égaliser","égarer","éjecter","élaborer","élargir","électron","élégant","éléphant","élève","éligible","élitisme","éloge","élucider","éluder","emballer","embellir","embryon","émeraude","émission","emmener","émotion","émouvoir","empereur","employer","emporter","emprise","émulsion","encadrer","enchère","enclave","encoche","endiguer","endosser","endroit","enduire","énergie","enfance","enfermer","enfouir","engager","engin","englober","énigme","enjamber","enjeu","enlever","ennemi","ennuyeux","enrichir","enrobage","enseigne","entasser","entendre","entier","entourer","entraver","énumérer","envahir","enviable","envoyer","enzyme","éolien","épaissir","épargne","épatant","épaule","épicerie","épidémie","épier","épilogue","épine","épisode","épitaphe","époque","épreuve","éprouver","épuisant","équerre","équipe","ériger","érosion","erreur","éruption","escalier","espadon","espèce","espiègle","espoir","esprit","esquiver","essayer","essence","essieu","essorer","estime","estomac","estrade","étagère","étaler","étanche","étatique","éteindre","étendoir","éternel","éthanol","éthique","ethnie","étirer","étoffer","étoile","étonnant","étourdir","étrange","étroit","étude","euphorie","évaluer","évasion","éventail","évidence","éviter","évolutif","évoquer","exact","exagérer","exaucer","exceller","excitant","exclusif","excuse","exécuter","exemple","exercer","exhaler","exhorter","exigence","exiler","exister","exotique","expédier","explorer","exposer","exprimer","exquis","extensif","extraire","exulter","fable","fabuleux","facette","facile","facture","faiblir","falaise","fameux","famille","farceur","farfelu","farine","farouche","fasciner","fatal","fatigue","faucon","fautif","faveur","favori","fébrile","féconder","fédérer","félin","femme","fémur","fendoir","féodal","fermer","féroce","ferveur","festival","feuille","feutre","février","fiasco","ficeler","fictif","fidèle","figure","filature","filetage","filière","filleul","filmer","filou","filtrer","financer","finir","fiole","firme","fissure","fixer","flairer","flamme","flasque","flatteur","fléau","flèche","fleur","flexion","flocon","flore","fluctuer","fluide","fluvial","folie","fonderie","fongible","fontaine","forcer","forgeron","formuler","fortune","fossile","foudre","fougère","fouiller","foulure","fourmi","fragile","fraise","franchir","frapper","frayeur","frégate","freiner","frelon","frémir","frénésie","frère","friable","friction","frisson","frivole","froid","fromage","frontal","frotter","fruit","fugitif","fuite","fureur","furieux","furtif","fusion","futur","gagner","galaxie","galerie","gambader","garantir","gardien","garnir","garrigue","gazelle","gazon","géant","gélatine","gélule","gendarme","général","génie","genou","gentil","géologie","géomètre","géranium","germe","gestuel","geyser","gibier","gicler","girafe","givre","glace","glaive","glisser","globe","gloire","glorieux","golfeur","gomme","gonfler","gorge","gorille","goudron","gouffre","goulot","goupille","gourmand","goutte","graduel","graffiti","graine","grand","grappin","gratuit","gravir","grenat","griffure","griller","grimper","grogner","gronder","grotte","groupe","gruger","grutier","gruyère","guépard","guerrier","guide","guimauve","guitare","gustatif","gymnaste","gyrostat","habitude","hachoir","halte","hameau","hangar","hanneton","haricot","harmonie","harpon","hasard","hélium","hématome","herbe","hérisson","hermine","héron","hésiter","heureux","hiberner","hibou","hilarant","histoire","hiver","homard","hommage","homogène","honneur","honorer","honteux","horde","horizon","horloge","hormone","horrible","houleux","housse","hublot","huileux","humain","humble","humide","humour","hurler","hydromel","hygiène","hymne","hypnose","idylle","ignorer","iguane","illicite","illusion","image","imbiber","imiter","immense","immobile","immuable","impact","impérial","implorer","imposer","imprimer","imputer","incarner","incendie","incident","incliner","incolore","indexer","indice","inductif","inédit","ineptie","inexact","infini","infliger","informer","infusion","ingérer","inhaler","inhiber","injecter","injure","innocent","inoculer","inonder","inscrire","insecte","insigne","insolite","inspirer","instinct","insulter","intact","intense","intime","intrigue","intuitif","inutile","invasion","inventer","inviter","invoquer","ironique","irradier","irréel","irriter","isoler","ivoire","ivresse","jaguar","jaillir","jambe","janvier","jardin","jauger","jaune","javelot","jetable","jeton","jeudi","jeunesse","joindre","joncher","jongler","joueur","jouissif","journal","jovial","joyau","joyeux","jubiler","jugement","junior","jupon","juriste","justice","juteux","juvénile","kayak","kimono","kiosque","label","labial","labourer","lacérer","lactose","lagune","laine","laisser","laitier","lambeau","lamelle","lampe","lanceur","langage","lanterne","lapin","largeur","larme","laurier","lavabo","lavoir","lecture","légal","léger","légume","lessive","lettre","levier","lexique","lézard","liasse","libérer","libre","licence","licorne","liège","lièvre","ligature","ligoter","ligue","limer","limite","limonade","limpide","linéaire","lingot","lionceau","liquide","lisière","lister","lithium","litige","littoral","livreur","logique","lointain","loisir","lombric","loterie","louer","lourd","loutre","louve","loyal","lubie","lucide","lucratif","lueur","lugubre","luisant","lumière","lunaire","lundi","luron","lutter","luxueux","machine","magasin","magenta","magique","maigre","maillon","maintien","mairie","maison","majorer","malaxer","maléfice","malheur","malice","mallette","mammouth","mandater","maniable","manquant","manteau","manuel","marathon","marbre","marchand","mardi","maritime","marqueur","marron","marteler","mascotte","massif","matériel","matière","matraque","maudire","maussade","mauve","maximal","méchant","méconnu","médaille","médecin","méditer","méduse","meilleur","mélange","mélodie","membre","mémoire","menacer","mener","menhir","mensonge","mentor","mercredi","mérite","merle","messager","mesure","métal","météore","méthode","métier","meuble","miauler","microbe","miette","mignon","migrer","milieu","million","mimique","mince","minéral","minimal","minorer","minute","miracle","miroiter","missile","mixte","mobile","moderne","moelleux","mondial","moniteur","monnaie","monotone","monstre","montagne","monument","moqueur","morceau","morsure","mortier","moteur","motif","mouche","moufle","moulin","mousson","mouton","mouvant","multiple","munition","muraille","murène","murmure","muscle","muséum","musicien","mutation","muter","mutuel","myriade","myrtille","mystère","mythique","nageur","nappe","narquois","narrer","natation","nation","nature","naufrage","nautique","navire","nébuleux","nectar","néfaste","négation","négliger","négocier","neige","nerveux","nettoyer","neurone","neutron","neveu","niche","nickel","nitrate","niveau","noble","nocif","nocturne","noirceur","noisette","nomade","nombreux","nommer","normatif","notable","notifier","notoire","nourrir","nouveau","novateur","novembre","novice","nuage","nuancer","nuire","nuisible","numéro","nuptial","nuque","nutritif","obéir","objectif","obliger","obscur","observer","obstacle","obtenir","obturer","occasion","occuper","océan","octobre","octroyer","octupler","oculaire","odeur","odorant","offenser","officier","offrir","ogive","oiseau","oisillon","olfactif","olivier","ombrage","omettre","onctueux","onduler","onéreux","onirique","opale","opaque","opérer","opinion","opportun","opprimer","opter","optique","orageux","orange","orbite","ordonner","oreille","organe","orgueil","orifice","ornement","orque","ortie","osciller","osmose","ossature","otarie","ouragan","ourson","outil","outrager","ouvrage","ovation","oxyde","oxygène","ozone","paisible","palace","palmarès","palourde","palper","panache","panda","pangolin","paniquer","panneau","panorama","pantalon","papaye","papier","papoter","papyrus","paradoxe","parcelle","paresse","parfumer","parler","parole","parrain","parsemer","partager","parure","parvenir","passion","pastèque","paternel","patience","patron","pavillon","pavoiser","payer","paysage","peigne","peintre","pelage","pélican","pelle","pelouse","peluche","pendule","pénétrer","pénible","pensif","pénurie","pépite","péplum","perdrix","perforer","période","permuter","perplexe","persil","perte","peser","pétale","petit","pétrir","peuple","pharaon","phobie","phoque","photon","phrase","physique","piano","pictural","pièce","pierre","pieuvre","pilote","pinceau","pipette","piquer","pirogue","piscine","piston","pivoter","pixel","pizza","placard","plafond","plaisir","planer","plaque","plastron","plateau","pleurer","plexus","pliage","plomb","plonger","pluie","plumage","pochette","poésie","poète","pointe","poirier","poisson","poivre","polaire","policier","pollen","polygone","pommade","pompier","ponctuel","pondérer","poney","portique","position","posséder","posture","potager","poteau","potion","pouce","poulain","poumon","pourpre","poussin","pouvoir","prairie","pratique","précieux","prédire","préfixe","prélude","prénom","présence","prétexte","prévoir","primitif","prince","prison","priver","problème","procéder","prodige","profond","progrès","proie","projeter","prologue","promener","propre","prospère","protéger","prouesse","proverbe","prudence","pruneau","psychose","public","puceron","puiser","pulpe","pulsar","punaise","punitif","pupitre","purifier","puzzle","pyramide","quasar","querelle","question","quiétude","quitter","quotient","racine","raconter","radieux","ragondin","raideur","raisin","ralentir","rallonge","ramasser","rapide","rasage","ratisser","ravager","ravin","rayonner","réactif","réagir","réaliser","réanimer","recevoir","réciter","réclamer","récolter","recruter","reculer","recycler","rédiger","redouter","refaire","réflexe","réformer","refrain","refuge","régalien","région","réglage","régulier","réitérer","rejeter","rejouer","relatif","relever","relief","remarque","remède","remise","remonter","remplir","remuer","renard","renfort","renifler","renoncer","rentrer","renvoi","replier","reporter","reprise","reptile","requin","réserve","résineux","résoudre","respect","rester","résultat","rétablir","retenir","réticule","retomber","retracer","réunion","réussir","revanche","revivre","révolte","révulsif","richesse","rideau","rieur","rigide","rigoler","rincer","riposter","risible","risque","rituel","rival","rivière","rocheux","romance","rompre","ronce","rondin","roseau","rosier","rotatif","rotor","rotule","rouge","rouille","rouleau","routine","royaume","ruban","rubis","ruche","ruelle","rugueux","ruiner","ruisseau","ruser","rustique","rythme","sabler","saboter","sabre","sacoche","safari","sagesse","saisir","salade","salive","salon","saluer","samedi","sanction","sanglier","sarcasme","sardine","saturer","saugrenu","saumon","sauter","sauvage","savant","savonner","scalpel","scandale","scélérat","scénario","sceptre","schéma","science","scinder","score","scrutin","sculpter","séance","sécable","sécher","secouer","sécréter","sédatif","séduire","seigneur","séjour","sélectif","semaine","sembler","semence","séminal","sénateur","sensible","sentence","séparer","séquence","serein","sergent","sérieux","serrure","sérum","service","sésame","sévir","sevrage","sextuple","sidéral","siècle","siéger","siffler","sigle","signal","silence","silicium","simple","sincère","sinistre","siphon","sirop","sismique","situer","skier","social","socle","sodium","soigneux","soldat","soleil","solitude","soluble","sombre","sommeil","somnoler","sonde","songeur","sonnette","sonore","sorcier","sortir","sosie","sottise","soucieux","soudure","souffle","soulever","soupape","source","soutirer","souvenir","spacieux","spatial","spécial","sphère","spiral","stable","station","sternum","stimulus","stipuler","strict","studieux","stupeur","styliste","sublime","substrat","subtil","subvenir","succès","sucre","suffixe","suggérer","suiveur","sulfate","superbe","supplier","surface","suricate","surmener","surprise","sursaut","survie","suspect","syllabe","symbole","symétrie","synapse","syntaxe","système","tabac","tablier","tactile","tailler","talent","talisman","talonner","tambour","tamiser","tangible","tapis","taquiner","tarder","tarif","tartine","tasse","tatami","tatouage","taupe","taureau","taxer","témoin","temporel","tenaille","tendre","teneur","tenir","tension","terminer","terne","terrible","tétine","texte","thème","théorie","thérapie","thorax","tibia","tiède","timide","tirelire","tiroir","tissu","titane","titre","tituber","toboggan","tolérant","tomate","tonique","tonneau","toponyme","torche","tordre","tornade","torpille","torrent","torse","tortue","totem","toucher","tournage","tousser","toxine","traction","trafic","tragique","trahir","train","trancher","travail","trèfle","tremper","trésor","treuil","triage","tribunal","tricoter","trilogie","triomphe","tripler","triturer","trivial","trombone","tronc","tropical","troupeau","tuile","tulipe","tumulte","tunnel","turbine","tuteur","tutoyer","tuyau","tympan","typhon","typique","tyran","ubuesque","ultime","ultrason","unanime","unifier","union","unique","unitaire","univers","uranium","urbain","urticant","usage","usine","usuel","usure","utile","utopie","vacarme","vaccin","vagabond","vague","vaillant","vaincre","vaisseau","valable","valise","vallon","valve","vampire","vanille","vapeur","varier","vaseux","vassal","vaste","vecteur","vedette","végétal","véhicule","veinard","véloce","vendredi","vénérer","venger","venimeux","ventouse","verdure","vérin","vernir","verrou","verser","vertu","veston","vétéran","vétuste","vexant","vexer","viaduc","viande","victoire","vidange","vidéo","vignette","vigueur","vilain","village","vinaigre","violon","vipère","virement","virtuose","virus","visage","viseur","vision","visqueux","visuel","vital","vitesse","viticole","vitrine","vivace","vivipare","vocation","voguer","voile","voisin","voiture","volaille","volcan","voltiger","volume","vorace","vortex","voter","vouloir","voyage","voyelle","wagon","xénon","yacht","zèbre","zénith","zeste","zoologie"]');
const require$$5 = /* @__PURE__ */ JSON.parse('["abaco","abbaglio","abbinato","abete","abisso","abolire","abrasivo","abrogato","accadere","accenno","accusato","acetone","achille","acido","acqua","acre","acrilico","acrobata","acuto","adagio","addebito","addome","adeguato","aderire","adipe","adottare","adulare","affabile","affetto","affisso","affranto","aforisma","afoso","africano","agave","agente","agevole","aggancio","agire","agitare","agonismo","agricolo","agrumeto","aguzzo","alabarda","alato","albatro","alberato","albo","albume","alce","alcolico","alettone","alfa","algebra","aliante","alibi","alimento","allagato","allegro","allievo","allodola","allusivo","almeno","alogeno","alpaca","alpestre","altalena","alterno","alticcio","altrove","alunno","alveolo","alzare","amalgama","amanita","amarena","ambito","ambrato","ameba","america","ametista","amico","ammasso","ammenda","ammirare","ammonito","amore","ampio","ampliare","amuleto","anacardo","anagrafe","analista","anarchia","anatra","anca","ancella","ancora","andare","andrea","anello","angelo","angolare","angusto","anima","annegare","annidato","anno","annuncio","anonimo","anticipo","anzi","apatico","apertura","apode","apparire","appetito","appoggio","approdo","appunto","aprile","arabica","arachide","aragosta","araldica","arancio","aratura","arazzo","arbitro","archivio","ardito","arenile","argento","argine","arguto","aria","armonia","arnese","arredato","arringa","arrosto","arsenico","arso","artefice","arzillo","asciutto","ascolto","asepsi","asettico","asfalto","asino","asola","aspirato","aspro","assaggio","asse","assoluto","assurdo","asta","astenuto","astice","astratto","atavico","ateismo","atomico","atono","attesa","attivare","attorno","attrito","attuale","ausilio","austria","autista","autonomo","autunno","avanzato","avere","avvenire","avviso","avvolgere","azione","azoto","azzimo","azzurro","babele","baccano","bacino","baco","badessa","badilata","bagnato","baita","balcone","baldo","balena","ballata","balzano","bambino","bandire","baraonda","barbaro","barca","baritono","barlume","barocco","basilico","basso","batosta","battuto","baule","bava","bavosa","becco","beffa","belgio","belva","benda","benevole","benigno","benzina","bere","berlina","beta","bibita","bici","bidone","bifido","biga","bilancia","bimbo","binocolo","biologo","bipede","bipolare","birbante","birra","biscotto","bisesto","bisnonno","bisonte","bisturi","bizzarro","blando","blatta","bollito","bonifico","bordo","bosco","botanico","bottino","bozzolo","braccio","bradipo","brama","branca","bravura","bretella","brevetto","brezza","briglia","brillante","brindare","broccolo","brodo","bronzina","brullo","bruno","bubbone","buca","budino","buffone","buio","bulbo","buono","burlone","burrasca","bussola","busta","cadetto","caduco","calamaro","calcolo","calesse","calibro","calmo","caloria","cambusa","camerata","camicia","cammino","camola","campale","canapa","candela","cane","canino","canotto","cantina","capace","capello","capitolo","capogiro","cappero","capra","capsula","carapace","carcassa","cardo","carisma","carovana","carretto","cartolina","casaccio","cascata","caserma","caso","cassone","castello","casuale","catasta","catena","catrame","cauto","cavillo","cedibile","cedrata","cefalo","celebre","cellulare","cena","cenone","centesimo","ceramica","cercare","certo","cerume","cervello","cesoia","cespo","ceto","chela","chiaro","chicca","chiedere","chimera","china","chirurgo","chitarra","ciao","ciclismo","cifrare","cigno","cilindro","ciottolo","circa","cirrosi","citrico","cittadino","ciuffo","civetta","civile","classico","clinica","cloro","cocco","codardo","codice","coerente","cognome","collare","colmato","colore","colposo","coltivato","colza","coma","cometa","commando","comodo","computer","comune","conciso","condurre","conferma","congelare","coniuge","connesso","conoscere","consumo","continuo","convegno","coperto","copione","coppia","copricapo","corazza","cordata","coricato","cornice","corolla","corpo","corredo","corsia","cortese","cosmico","costante","cottura","covato","cratere","cravatta","creato","credere","cremoso","crescita","creta","criceto","crinale","crisi","critico","croce","cronaca","crostata","cruciale","crusca","cucire","cuculo","cugino","cullato","cupola","curatore","cursore","curvo","cuscino","custode","dado","daino","dalmata","damerino","daniela","dannoso","danzare","datato","davanti","davvero","debutto","decennio","deciso","declino","decollo","decreto","dedicato","definito","deforme","degno","delegare","delfino","delirio","delta","demenza","denotato","dentro","deposito","derapata","derivare","deroga","descritto","deserto","desiderio","desumere","detersivo","devoto","diametro","dicembre","diedro","difeso","diffuso","digerire","digitale","diluvio","dinamico","dinnanzi","dipinto","diploma","dipolo","diradare","dire","dirotto","dirupo","disagio","discreto","disfare","disgelo","disposto","distanza","disumano","dito","divano","divelto","dividere","divorato","doblone","docente","doganale","dogma","dolce","domato","domenica","dominare","dondolo","dono","dormire","dote","dottore","dovuto","dozzina","drago","druido","dubbio","dubitare","ducale","duna","duomo","duplice","duraturo","ebano","eccesso","ecco","eclissi","economia","edera","edicola","edile","editoria","educare","egemonia","egli","egoismo","egregio","elaborato","elargire","elegante","elencato","eletto","elevare","elfico","elica","elmo","elsa","eluso","emanato","emblema","emesso","emiro","emotivo","emozione","empirico","emulo","endemico","enduro","energia","enfasi","enoteca","entrare","enzima","epatite","epilogo","episodio","epocale","eppure","equatore","erario","erba","erboso","erede","eremita","erigere","ermetico","eroe","erosivo","errante","esagono","esame","esanime","esaudire","esca","esempio","esercito","esibito","esigente","esistere","esito","esofago","esortato","esoso","espanso","espresso","essenza","esso","esteso","estimare","estonia","estroso","esultare","etilico","etnico","etrusco","etto","euclideo","europa","evaso","evidenza","evitato","evoluto","evviva","fabbrica","faccenda","fachiro","falco","famiglia","fanale","fanfara","fango","fantasma","fare","farfalla","farinoso","farmaco","fascia","fastoso","fasullo","faticare","fato","favoloso","febbre","fecola","fede","fegato","felpa","feltro","femmina","fendere","fenomeno","fermento","ferro","fertile","fessura","festivo","fetta","feudo","fiaba","fiducia","fifa","figurato","filo","finanza","finestra","finire","fiore","fiscale","fisico","fiume","flacone","flamenco","flebo","flemma","florido","fluente","fluoro","fobico","focaccia","focoso","foderato","foglio","folata","folclore","folgore","fondente","fonetico","fonia","fontana","forbito","forchetta","foresta","formica","fornaio","foro","fortezza","forzare","fosfato","fosso","fracasso","frana","frassino","fratello","freccetta","frenata","fresco","frigo","frollino","fronde","frugale","frutta","fucilata","fucsia","fuggente","fulmine","fulvo","fumante","fumetto","fumoso","fune","funzione","fuoco","furbo","furgone","furore","fuso","futile","gabbiano","gaffe","galateo","gallina","galoppo","gambero","gamma","garanzia","garbo","garofano","garzone","gasdotto","gasolio","gastrico","gatto","gaudio","gazebo","gazzella","geco","gelatina","gelso","gemello","gemmato","gene","genitore","gennaio","genotipo","gergo","ghepardo","ghiaccio","ghisa","giallo","gilda","ginepro","giocare","gioiello","giorno","giove","girato","girone","gittata","giudizio","giurato","giusto","globulo","glutine","gnomo","gobba","golf","gomito","gommone","gonfio","gonna","governo","gracile","grado","grafico","grammo","grande","grattare","gravoso","grazia","greca","gregge","grifone","grigio","grinza","grotta","gruppo","guadagno","guaio","guanto","guardare","gufo","guidare","ibernato","icona","identico","idillio","idolo","idra","idrico","idrogeno","igiene","ignaro","ignorato","ilare","illeso","illogico","illudere","imballo","imbevuto","imbocco","imbuto","immane","immerso","immolato","impacco","impeto","impiego","importo","impronta","inalare","inarcare","inattivo","incanto","incendio","inchino","incisivo","incluso","incontro","incrocio","incubo","indagine","india","indole","inedito","infatti","infilare","inflitto","ingaggio","ingegno","inglese","ingordo","ingrosso","innesco","inodore","inoltrare","inondato","insano","insetto","insieme","insonnia","insulina","intasato","intero","intonaco","intuito","inumidire","invalido","invece","invito","iperbole","ipnotico","ipotesi","ippica","iride","irlanda","ironico","irrigato","irrorare","isolato","isotopo","isterico","istituto","istrice","italia","iterare","labbro","labirinto","lacca","lacerato","lacrima","lacuna","laddove","lago","lampo","lancetta","lanterna","lardoso","larga","laringe","lastra","latenza","latino","lattuga","lavagna","lavoro","legale","leggero","lembo","lentezza","lenza","leone","lepre","lesivo","lessato","lesto","letterale","leva","levigato","libero","lido","lievito","lilla","limatura","limitare","limpido","lineare","lingua","liquido","lira","lirica","lisca","lite","litigio","livrea","locanda","lode","logica","lombare","londra","longevo","loquace","lorenzo","loto","lotteria","luce","lucidato","lumaca","luminoso","lungo","lupo","luppolo","lusinga","lusso","lutto","macabro","macchina","macero","macinato","madama","magico","maglia","magnete","magro","maiolica","malafede","malgrado","malinteso","malsano","malto","malumore","mana","mancia","mandorla","mangiare","manifesto","mannaro","manovra","mansarda","mantide","manubrio","mappa","maratona","marcire","maretta","marmo","marsupio","maschera","massaia","mastino","materasso","matricola","mattone","maturo","mazurca","meandro","meccanico","mecenate","medesimo","meditare","mega","melassa","melis","melodia","meninge","meno","mensola","mercurio","merenda","merlo","meschino","mese","messere","mestolo","metallo","metodo","mettere","miagolare","mica","micelio","michele","microbo","midollo","miele","migliore","milano","milite","mimosa","minerale","mini","minore","mirino","mirtillo","miscela","missiva","misto","misurare","mitezza","mitigare","mitra","mittente","mnemonico","modello","modifica","modulo","mogano","mogio","mole","molosso","monastero","monco","mondina","monetario","monile","monotono","monsone","montato","monviso","mora","mordere","morsicato","mostro","motivato","motosega","motto","movenza","movimento","mozzo","mucca","mucosa","muffa","mughetto","mugnaio","mulatto","mulinello","multiplo","mummia","munto","muovere","murale","musa","muscolo","musica","mutevole","muto","nababbo","nafta","nanometro","narciso","narice","narrato","nascere","nastrare","naturale","nautica","naviglio","nebulosa","necrosi","negativo","negozio","nemmeno","neofita","neretto","nervo","nessuno","nettuno","neutrale","neve","nevrotico","nicchia","ninfa","nitido","nobile","nocivo","nodo","nome","nomina","nordico","normale","norvegese","nostrano","notare","notizia","notturno","novella","nucleo","nulla","numero","nuovo","nutrire","nuvola","nuziale","oasi","obbedire","obbligo","obelisco","oblio","obolo","obsoleto","occasione","occhio","occidente","occorrere","occultare","ocra","oculato","odierno","odorare","offerta","offrire","offuscato","oggetto","oggi","ognuno","olandese","olfatto","oliato","oliva","ologramma","oltre","omaggio","ombelico","ombra","omega","omissione","ondoso","onere","onice","onnivoro","onorevole","onta","operato","opinione","opposto","oracolo","orafo","ordine","orecchino","orefice","orfano","organico","origine","orizzonte","orma","ormeggio","ornativo","orologio","orrendo","orribile","ortensia","ortica","orzata","orzo","osare","oscurare","osmosi","ospedale","ospite","ossa","ossidare","ostacolo","oste","otite","otre","ottagono","ottimo","ottobre","ovale","ovest","ovino","oviparo","ovocito","ovunque","ovviare","ozio","pacchetto","pace","pacifico","padella","padrone","paese","paga","pagina","palazzina","palesare","pallido","palo","palude","pandoro","pannello","paolo","paonazzo","paprica","parabola","parcella","parere","pargolo","pari","parlato","parola","partire","parvenza","parziale","passivo","pasticca","patacca","patologia","pattume","pavone","peccato","pedalare","pedonale","peggio","peloso","penare","pendice","penisola","pennuto","penombra","pensare","pentola","pepe","pepita","perbene","percorso","perdonato","perforare","pergamena","periodo","permesso","perno","perplesso","persuaso","pertugio","pervaso","pesatore","pesista","peso","pestifero","petalo","pettine","petulante","pezzo","piacere","pianta","piattino","piccino","picozza","piega","pietra","piffero","pigiama","pigolio","pigro","pila","pilifero","pillola","pilota","pimpante","pineta","pinna","pinolo","pioggia","piombo","piramide","piretico","pirite","pirolisi","pitone","pizzico","placebo","planare","plasma","platano","plenario","pochezza","poderoso","podismo","poesia","poggiare","polenta","poligono","pollice","polmonite","polpetta","polso","poltrona","polvere","pomice","pomodoro","ponte","popoloso","porfido","poroso","porpora","porre","portata","posa","positivo","possesso","postulato","potassio","potere","pranzo","prassi","pratica","precluso","predica","prefisso","pregiato","prelievo","premere","prenotare","preparato","presenza","pretesto","prevalso","prima","principe","privato","problema","procura","produrre","profumo","progetto","prolunga","promessa","pronome","proposta","proroga","proteso","prova","prudente","prugna","prurito","psiche","pubblico","pudica","pugilato","pugno","pulce","pulito","pulsante","puntare","pupazzo","pupilla","puro","quadro","qualcosa","quasi","querela","quota","raccolto","raddoppio","radicale","radunato","raffica","ragazzo","ragione","ragno","ramarro","ramingo","ramo","randagio","rantolare","rapato","rapina","rappreso","rasatura","raschiato","rasente","rassegna","rastrello","rata","ravveduto","reale","recepire","recinto","recluta","recondito","recupero","reddito","redimere","regalato","registro","regola","regresso","relazione","remare","remoto","renna","replica","reprimere","reputare","resa","residente","responso","restauro","rete","retina","retorica","rettifica","revocato","riassunto","ribadire","ribelle","ribrezzo","ricarica","ricco","ricevere","riciclato","ricordo","ricreduto","ridicolo","ridurre","rifasare","riflesso","riforma","rifugio","rigare","rigettato","righello","rilassato","rilevato","rimanere","rimbalzo","rimedio","rimorchio","rinascita","rincaro","rinforzo","rinnovo","rinomato","rinsavito","rintocco","rinuncia","rinvenire","riparato","ripetuto","ripieno","riportare","ripresa","ripulire","risata","rischio","riserva","risibile","riso","rispetto","ristoro","risultato","risvolto","ritardo","ritegno","ritmico","ritrovo","riunione","riva","riverso","rivincita","rivolto","rizoma","roba","robotico","robusto","roccia","roco","rodaggio","rodere","roditore","rogito","rollio","romantico","rompere","ronzio","rosolare","rospo","rotante","rotondo","rotula","rovescio","rubizzo","rubrica","ruga","rullino","rumine","rumoroso","ruolo","rupe","russare","rustico","sabato","sabbiare","sabotato","sagoma","salasso","saldatura","salgemma","salivare","salmone","salone","saltare","saluto","salvo","sapere","sapido","saporito","saraceno","sarcasmo","sarto","sassoso","satellite","satira","satollo","saturno","savana","savio","saziato","sbadiglio","sbalzo","sbancato","sbarra","sbattere","sbavare","sbendare","sbirciare","sbloccato","sbocciato","sbrinare","sbruffone","sbuffare","scabroso","scadenza","scala","scambiare","scandalo","scapola","scarso","scatenare","scavato","scelto","scenico","scettro","scheda","schiena","sciarpa","scienza","scindere","scippo","sciroppo","scivolo","sclerare","scodella","scolpito","scomparto","sconforto","scoprire","scorta","scossone","scozzese","scriba","scrollare","scrutinio","scuderia","scultore","scuola","scuro","scusare","sdebitare","sdoganare","seccatura","secondo","sedano","seggiola","segnalato","segregato","seguito","selciato","selettivo","sella","selvaggio","semaforo","sembrare","seme","seminato","sempre","senso","sentire","sepolto","sequenza","serata","serbato","sereno","serio","serpente","serraglio","servire","sestina","setola","settimana","sfacelo","sfaldare","sfamato","sfarzoso","sfaticato","sfera","sfida","sfilato","sfinge","sfocato","sfoderare","sfogo","sfoltire","sforzato","sfratto","sfruttato","sfuggito","sfumare","sfuso","sgabello","sgarbato","sgonfiare","sgorbio","sgrassato","sguardo","sibilo","siccome","sierra","sigla","signore","silenzio","sillaba","simbolo","simpatico","simulato","sinfonia","singolo","sinistro","sino","sintesi","sinusoide","sipario","sisma","sistole","situato","slitta","slogatura","sloveno","smarrito","smemorato","smentito","smeraldo","smilzo","smontare","smottato","smussato","snellire","snervato","snodo","sobbalzo","sobrio","soccorso","sociale","sodale","soffitto","sogno","soldato","solenne","solido","sollazzo","solo","solubile","solvente","somatico","somma","sonda","sonetto","sonnifero","sopire","soppeso","sopra","sorgere","sorpasso","sorriso","sorso","sorteggio","sorvolato","sospiro","sosta","sottile","spada","spalla","spargere","spatola","spavento","spazzola","specie","spedire","spegnere","spelatura","speranza","spessore","spettrale","spezzato","spia","spigoloso","spillato","spinoso","spirale","splendido","sportivo","sposo","spranga","sprecare","spronato","spruzzo","spuntino","squillo","sradicare","srotolato","stabile","stacco","staffa","stagnare","stampato","stantio","starnuto","stasera","statuto","stelo","steppa","sterzo","stiletto","stima","stirpe","stivale","stizzoso","stonato","storico","strappo","stregato","stridulo","strozzare","strutto","stuccare","stufo","stupendo","subentro","succoso","sudore","suggerito","sugo","sultano","suonare","superbo","supporto","surgelato","surrogato","sussurro","sutura","svagare","svedese","sveglio","svelare","svenuto","svezia","sviluppo","svista","svizzera","svolta","svuotare","tabacco","tabulato","tacciare","taciturno","tale","talismano","tampone","tannino","tara","tardivo","targato","tariffa","tarpare","tartaruga","tasto","tattico","taverna","tavolata","tazza","teca","tecnico","telefono","temerario","tempo","temuto","tendone","tenero","tensione","tentacolo","teorema","terme","terrazzo","terzetto","tesi","tesserato","testato","tetro","tettoia","tifare","tigella","timbro","tinto","tipico","tipografo","tiraggio","tiro","titanio","titolo","titubante","tizio","tizzone","toccare","tollerare","tolto","tombola","tomo","tonfo","tonsilla","topazio","topologia","toppa","torba","tornare","torrone","tortora","toscano","tossire","tostatura","totano","trabocco","trachea","trafila","tragedia","tralcio","tramonto","transito","trapano","trarre","trasloco","trattato","trave","treccia","tremolio","trespolo","tributo","tricheco","trifoglio","trillo","trincea","trio","tristezza","triturato","trivella","tromba","trono","troppo","trottola","trovare","truccato","tubatura","tuffato","tulipano","tumulto","tunisia","turbare","turchino","tuta","tutela","ubicato","uccello","uccisore","udire","uditivo","uffa","ufficio","uguale","ulisse","ultimato","umano","umile","umorismo","uncinetto","ungere","ungherese","unicorno","unificato","unisono","unitario","unte","uovo","upupa","uragano","urgenza","urlo","usanza","usato","uscito","usignolo","usuraio","utensile","utilizzo","utopia","vacante","vaccinato","vagabondo","vagliato","valanga","valgo","valico","valletta","valoroso","valutare","valvola","vampata","vangare","vanitoso","vano","vantaggio","vanvera","vapore","varano","varcato","variante","vasca","vedetta","vedova","veduto","vegetale","veicolo","velcro","velina","velluto","veloce","venato","vendemmia","vento","verace","verbale","vergogna","verifica","vero","verruca","verticale","vescica","vessillo","vestale","veterano","vetrina","vetusto","viandante","vibrante","vicenda","vichingo","vicinanza","vidimare","vigilia","vigneto","vigore","vile","villano","vimini","vincitore","viola","vipera","virgola","virologo","virulento","viscoso","visione","vispo","vissuto","visura","vita","vitello","vittima","vivanda","vivido","viziare","voce","voga","volatile","volere","volpe","voragine","vulcano","zampogna","zanna","zappato","zattera","zavorra","zefiro","zelante","zelo","zenzero","zerbino","zibetto","zinco","zircone","zitto","zolla","zotico","zucchero","zufolo","zulu","zuppa"]');
const require$$6 = /* @__PURE__ */ JSON.parse('["ábaco","abdomen","abeja","abierto","abogado","abono","aborto","abrazo","abrir","abuelo","abuso","acabar","academia","acceso","acción","aceite","acelga","acento","aceptar","ácido","aclarar","acné","acoger","acoso","activo","acto","actriz","actuar","acudir","acuerdo","acusar","adicto","admitir","adoptar","adorno","aduana","adulto","aéreo","afectar","afición","afinar","afirmar","ágil","agitar","agonía","agosto","agotar","agregar","agrio","agua","agudo","águila","aguja","ahogo","ahorro","aire","aislar","ajedrez","ajeno","ajuste","alacrán","alambre","alarma","alba","álbum","alcalde","aldea","alegre","alejar","alerta","aleta","alfiler","alga","algodón","aliado","aliento","alivio","alma","almeja","almíbar","altar","alteza","altivo","alto","altura","alumno","alzar","amable","amante","amapola","amargo","amasar","ámbar","ámbito","ameno","amigo","amistad","amor","amparo","amplio","ancho","anciano","ancla","andar","andén","anemia","ángulo","anillo","ánimo","anís","anotar","antena","antiguo","antojo","anual","anular","anuncio","añadir","añejo","año","apagar","aparato","apetito","apio","aplicar","apodo","aporte","apoyo","aprender","aprobar","apuesta","apuro","arado","araña","arar","árbitro","árbol","arbusto","archivo","arco","arder","ardilla","arduo","área","árido","aries","armonía","arnés","aroma","arpa","arpón","arreglo","arroz","arruga","arte","artista","asa","asado","asalto","ascenso","asegurar","aseo","asesor","asiento","asilo","asistir","asno","asombro","áspero","astilla","astro","astuto","asumir","asunto","atajo","ataque","atar","atento","ateo","ático","atleta","átomo","atraer","atroz","atún","audaz","audio","auge","aula","aumento","ausente","autor","aval","avance","avaro","ave","avellana","avena","avestruz","avión","aviso","ayer","ayuda","ayuno","azafrán","azar","azote","azúcar","azufre","azul","baba","babor","bache","bahía","baile","bajar","balanza","balcón","balde","bambú","banco","banda","baño","barba","barco","barniz","barro","báscula","bastón","basura","batalla","batería","batir","batuta","baúl","bazar","bebé","bebida","bello","besar","beso","bestia","bicho","bien","bingo","blanco","bloque","blusa","boa","bobina","bobo","boca","bocina","boda","bodega","boina","bola","bolero","bolsa","bomba","bondad","bonito","bono","bonsái","borde","borrar","bosque","bote","botín","bóveda","bozal","bravo","brazo","brecha","breve","brillo","brinco","brisa","broca","broma","bronce","brote","bruja","brusco","bruto","buceo","bucle","bueno","buey","bufanda","bufón","búho","buitre","bulto","burbuja","burla","burro","buscar","butaca","buzón","caballo","cabeza","cabina","cabra","cacao","cadáver","cadena","caer","café","caída","caimán","caja","cajón","cal","calamar","calcio","caldo","calidad","calle","calma","calor","calvo","cama","cambio","camello","camino","campo","cáncer","candil","canela","canguro","canica","canto","caña","cañón","caoba","caos","capaz","capitán","capote","captar","capucha","cara","carbón","cárcel","careta","carga","cariño","carne","carpeta","carro","carta","casa","casco","casero","caspa","castor","catorce","catre","caudal","causa","cazo","cebolla","ceder","cedro","celda","célebre","celoso","célula","cemento","ceniza","centro","cerca","cerdo","cereza","cero","cerrar","certeza","césped","cetro","chacal","chaleco","champú","chancla","chapa","charla","chico","chiste","chivo","choque","choza","chuleta","chupar","ciclón","ciego","cielo","cien","cierto","cifra","cigarro","cima","cinco","cine","cinta","ciprés","circo","ciruela","cisne","cita","ciudad","clamor","clan","claro","clase","clave","cliente","clima","clínica","cobre","cocción","cochino","cocina","coco","código","codo","cofre","coger","cohete","cojín","cojo","cola","colcha","colegio","colgar","colina","collar","colmo","columna","combate","comer","comida","cómodo","compra","conde","conejo","conga","conocer","consejo","contar","copa","copia","corazón","corbata","corcho","cordón","corona","correr","coser","cosmos","costa","cráneo","cráter","crear","crecer","creído","crema","cría","crimen","cripta","crisis","cromo","crónica","croqueta","crudo","cruz","cuadro","cuarto","cuatro","cubo","cubrir","cuchara","cuello","cuento","cuerda","cuesta","cueva","cuidar","culebra","culpa","culto","cumbre","cumplir","cuna","cuneta","cuota","cupón","cúpula","curar","curioso","curso","curva","cutis","dama","danza","dar","dardo","dátil","deber","débil","década","decir","dedo","defensa","definir","dejar","delfín","delgado","delito","demora","denso","dental","deporte","derecho","derrota","desayuno","deseo","desfile","desnudo","destino","desvío","detalle","detener","deuda","día","diablo","diadema","diamante","diana","diario","dibujo","dictar","diente","dieta","diez","difícil","digno","dilema","diluir","dinero","directo","dirigir","disco","diseño","disfraz","diva","divino","doble","doce","dolor","domingo","don","donar","dorado","dormir","dorso","dos","dosis","dragón","droga","ducha","duda","duelo","dueño","dulce","dúo","duque","durar","dureza","duro","ébano","ebrio","echar","eco","ecuador","edad","edición","edificio","editor","educar","efecto","eficaz","eje","ejemplo","elefante","elegir","elemento","elevar","elipse","élite","elixir","elogio","eludir","embudo","emitir","emoción","empate","empeño","empleo","empresa","enano","encargo","enchufe","encía","enemigo","enero","enfado","enfermo","engaño","enigma","enlace","enorme","enredo","ensayo","enseñar","entero","entrar","envase","envío","época","equipo","erizo","escala","escena","escolar","escribir","escudo","esencia","esfera","esfuerzo","espada","espejo","espía","esposa","espuma","esquí","estar","este","estilo","estufa","etapa","eterno","ética","etnia","evadir","evaluar","evento","evitar","exacto","examen","exceso","excusa","exento","exigir","exilio","existir","éxito","experto","explicar","exponer","extremo","fábrica","fábula","fachada","fácil","factor","faena","faja","falda","fallo","falso","faltar","fama","familia","famoso","faraón","farmacia","farol","farsa","fase","fatiga","fauna","favor","fax","febrero","fecha","feliz","feo","feria","feroz","fértil","fervor","festín","fiable","fianza","fiar","fibra","ficción","ficha","fideo","fiebre","fiel","fiera","fiesta","figura","fijar","fijo","fila","filete","filial","filtro","fin","finca","fingir","finito","firma","flaco","flauta","flecha","flor","flota","fluir","flujo","flúor","fobia","foca","fogata","fogón","folio","folleto","fondo","forma","forro","fortuna","forzar","fosa","foto","fracaso","frágil","franja","frase","fraude","freír","freno","fresa","frío","frito","fruta","fuego","fuente","fuerza","fuga","fumar","función","funda","furgón","furia","fusil","fútbol","futuro","gacela","gafas","gaita","gajo","gala","galería","gallo","gamba","ganar","gancho","ganga","ganso","garaje","garza","gasolina","gastar","gato","gavilán","gemelo","gemir","gen","género","genio","gente","geranio","gerente","germen","gesto","gigante","gimnasio","girar","giro","glaciar","globo","gloria","gol","golfo","goloso","golpe","goma","gordo","gorila","gorra","gota","goteo","gozar","grada","gráfico","grano","grasa","gratis","grave","grieta","grillo","gripe","gris","grito","grosor","grúa","grueso","grumo","grupo","guante","guapo","guardia","guerra","guía","guiño","guion","guiso","guitarra","gusano","gustar","haber","hábil","hablar","hacer","hacha","hada","hallar","hamaca","harina","haz","hazaña","hebilla","hebra","hecho","helado","helio","hembra","herir","hermano","héroe","hervir","hielo","hierro","hígado","higiene","hijo","himno","historia","hocico","hogar","hoguera","hoja","hombre","hongo","honor","honra","hora","hormiga","horno","hostil","hoyo","hueco","huelga","huerta","hueso","huevo","huida","huir","humano","húmedo","humilde","humo","hundir","huracán","hurto","icono","ideal","idioma","ídolo","iglesia","iglú","igual","ilegal","ilusión","imagen","imán","imitar","impar","imperio","imponer","impulso","incapaz","índice","inerte","infiel","informe","ingenio","inicio","inmenso","inmune","innato","insecto","instante","interés","íntimo","intuir","inútil","invierno","ira","iris","ironía","isla","islote","jabalí","jabón","jamón","jarabe","jardín","jarra","jaula","jazmín","jefe","jeringa","jinete","jornada","joroba","joven","joya","juerga","jueves","juez","jugador","jugo","juguete","juicio","junco","jungla","junio","juntar","júpiter","jurar","justo","juvenil","juzgar","kilo","koala","labio","lacio","lacra","lado","ladrón","lagarto","lágrima","laguna","laico","lamer","lámina","lámpara","lana","lancha","langosta","lanza","lápiz","largo","larva","lástima","lata","látex","latir","laurel","lavar","lazo","leal","lección","leche","lector","leer","legión","legumbre","lejano","lengua","lento","leña","león","leopardo","lesión","letal","letra","leve","leyenda","libertad","libro","licor","líder","lidiar","lienzo","liga","ligero","lima","límite","limón","limpio","lince","lindo","línea","lingote","lino","linterna","líquido","liso","lista","litera","litio","litro","llaga","llama","llanto","llave","llegar","llenar","llevar","llorar","llover","lluvia","lobo","loción","loco","locura","lógica","logro","lombriz","lomo","lonja","lote","lucha","lucir","lugar","lujo","luna","lunes","lupa","lustro","luto","luz","maceta","macho","madera","madre","maduro","maestro","mafia","magia","mago","maíz","maldad","maleta","malla","malo","mamá","mambo","mamut","manco","mando","manejar","manga","maniquí","manjar","mano","manso","manta","mañana","mapa","máquina","mar","marco","marea","marfil","margen","marido","mármol","marrón","martes","marzo","masa","máscara","masivo","matar","materia","matiz","matriz","máximo","mayor","mazorca","mecha","medalla","medio","médula","mejilla","mejor","melena","melón","memoria","menor","mensaje","mente","menú","mercado","merengue","mérito","mes","mesón","meta","meter","método","metro","mezcla","miedo","miel","miembro","miga","mil","milagro","militar","millón","mimo","mina","minero","mínimo","minuto","miope","mirar","misa","miseria","misil","mismo","mitad","mito","mochila","moción","moda","modelo","moho","mojar","molde","moler","molino","momento","momia","monarca","moneda","monja","monto","moño","morada","morder","moreno","morir","morro","morsa","mortal","mosca","mostrar","motivo","mover","móvil","mozo","mucho","mudar","mueble","muela","muerte","muestra","mugre","mujer","mula","muleta","multa","mundo","muñeca","mural","muro","músculo","museo","musgo","música","muslo","nácar","nación","nadar","naipe","naranja","nariz","narrar","nasal","natal","nativo","natural","náusea","naval","nave","navidad","necio","néctar","negar","negocio","negro","neón","nervio","neto","neutro","nevar","nevera","nicho","nido","niebla","nieto","niñez","niño","nítido","nivel","nobleza","noche","nómina","noria","norma","norte","nota","noticia","novato","novela","novio","nube","nuca","núcleo","nudillo","nudo","nuera","nueve","nuez","nulo","número","nutria","oasis","obeso","obispo","objeto","obra","obrero","observar","obtener","obvio","oca","ocaso","océano","ochenta","ocho","ocio","ocre","octavo","octubre","oculto","ocupar","ocurrir","odiar","odio","odisea","oeste","ofensa","oferta","oficio","ofrecer","ogro","oído","oír","ojo","ola","oleada","olfato","olivo","olla","olmo","olor","olvido","ombligo","onda","onza","opaco","opción","ópera","opinar","oponer","optar","óptica","opuesto","oración","orador","oral","órbita","orca","orden","oreja","órgano","orgía","orgullo","oriente","origen","orilla","oro","orquesta","oruga","osadía","oscuro","osezno","oso","ostra","otoño","otro","oveja","óvulo","óxido","oxígeno","oyente","ozono","pacto","padre","paella","página","pago","país","pájaro","palabra","palco","paleta","pálido","palma","paloma","palpar","pan","panal","pánico","pantera","pañuelo","papá","papel","papilla","paquete","parar","parcela","pared","parir","paro","párpado","parque","párrafo","parte","pasar","paseo","pasión","paso","pasta","pata","patio","patria","pausa","pauta","pavo","payaso","peatón","pecado","pecera","pecho","pedal","pedir","pegar","peine","pelar","peldaño","pelea","peligro","pellejo","pelo","peluca","pena","pensar","peñón","peón","peor","pepino","pequeño","pera","percha","perder","pereza","perfil","perico","perla","permiso","perro","persona","pesa","pesca","pésimo","pestaña","pétalo","petróleo","pez","pezuña","picar","pichón","pie","piedra","pierna","pieza","pijama","pilar","piloto","pimienta","pino","pintor","pinza","piña","piojo","pipa","pirata","pisar","piscina","piso","pista","pitón","pizca","placa","plan","plata","playa","plaza","pleito","pleno","plomo","pluma","plural","pobre","poco","poder","podio","poema","poesía","poeta","polen","policía","pollo","polvo","pomada","pomelo","pomo","pompa","poner","porción","portal","posada","poseer","posible","poste","potencia","potro","pozo","prado","precoz","pregunta","premio","prensa","preso","previo","primo","príncipe","prisión","privar","proa","probar","proceso","producto","proeza","profesor","programa","prole","promesa","pronto","propio","próximo","prueba","público","puchero","pudor","pueblo","puerta","puesto","pulga","pulir","pulmón","pulpo","pulso","puma","punto","puñal","puño","pupa","pupila","puré","quedar","queja","quemar","querer","queso","quieto","química","quince","quitar","rábano","rabia","rabo","ración","radical","raíz","rama","rampa","rancho","rango","rapaz","rápido","rapto","rasgo","raspa","rato","rayo","raza","razón","reacción","realidad","rebaño","rebote","recaer","receta","rechazo","recoger","recreo","recto","recurso","red","redondo","reducir","reflejo","reforma","refrán","refugio","regalo","regir","regla","regreso","rehén","reino","reír","reja","relato","relevo","relieve","relleno","reloj","remar","remedio","remo","rencor","rendir","renta","reparto","repetir","reposo","reptil","res","rescate","resina","respeto","resto","resumen","retiro","retorno","retrato","reunir","revés","revista","rey","rezar","rico","riego","rienda","riesgo","rifa","rígido","rigor","rincón","riñón","río","riqueza","risa","ritmo","rito","rizo","roble","roce","rociar","rodar","rodeo","rodilla","roer","rojizo","rojo","romero","romper","ron","ronco","ronda","ropa","ropero","rosa","rosca","rostro","rotar","rubí","rubor","rudo","rueda","rugir","ruido","ruina","ruleta","rulo","rumbo","rumor","ruptura","ruta","rutina","sábado","saber","sabio","sable","sacar","sagaz","sagrado","sala","saldo","salero","salir","salmón","salón","salsa","salto","salud","salvar","samba","sanción","sandía","sanear","sangre","sanidad","sano","santo","sapo","saque","sardina","sartén","sastre","satán","sauna","saxofón","sección","seco","secreto","secta","sed","seguir","seis","sello","selva","semana","semilla","senda","sensor","señal","señor","separar","sepia","sequía","ser","serie","sermón","servir","sesenta","sesión","seta","setenta","severo","sexo","sexto","sidra","siesta","siete","siglo","signo","sílaba","silbar","silencio","silla","símbolo","simio","sirena","sistema","sitio","situar","sobre","socio","sodio","sol","solapa","soldado","soledad","sólido","soltar","solución","sombra","sondeo","sonido","sonoro","sonrisa","sopa","soplar","soporte","sordo","sorpresa","sorteo","sostén","sótano","suave","subir","suceso","sudor","suegra","suelo","sueño","suerte","sufrir","sujeto","sultán","sumar","superar","suplir","suponer","supremo","sur","surco","sureño","surgir","susto","sutil","tabaco","tabique","tabla","tabú","taco","tacto","tajo","talar","talco","talento","talla","talón","tamaño","tambor","tango","tanque","tapa","tapete","tapia","tapón","taquilla","tarde","tarea","tarifa","tarjeta","tarot","tarro","tarta","tatuaje","tauro","taza","tazón","teatro","techo","tecla","técnica","tejado","tejer","tejido","tela","teléfono","tema","temor","templo","tenaz","tender","tener","tenis","tenso","teoría","terapia","terco","término","ternura","terror","tesis","tesoro","testigo","tetera","texto","tez","tibio","tiburón","tiempo","tienda","tierra","tieso","tigre","tijera","tilde","timbre","tímido","timo","tinta","tío","típico","tipo","tira","tirón","titán","títere","título","tiza","toalla","tobillo","tocar","tocino","todo","toga","toldo","tomar","tono","tonto","topar","tope","toque","tórax","torero","tormenta","torneo","toro","torpedo","torre","torso","tortuga","tos","tosco","toser","tóxico","trabajo","tractor","traer","tráfico","trago","traje","tramo","trance","trato","trauma","trazar","trébol","tregua","treinta","tren","trepar","tres","tribu","trigo","tripa","triste","triunfo","trofeo","trompa","tronco","tropa","trote","trozo","truco","trueno","trufa","tubería","tubo","tuerto","tumba","tumor","túnel","túnica","turbina","turismo","turno","tutor","ubicar","úlcera","umbral","unidad","unir","universo","uno","untar","uña","urbano","urbe","urgente","urna","usar","usuario","útil","utopía","uva","vaca","vacío","vacuna","vagar","vago","vaina","vajilla","vale","válido","valle","valor","válvula","vampiro","vara","variar","varón","vaso","vecino","vector","vehículo","veinte","vejez","vela","velero","veloz","vena","vencer","venda","veneno","vengar","venir","venta","venus","ver","verano","verbo","verde","vereda","verja","verso","verter","vía","viaje","vibrar","vicio","víctima","vida","vídeo","vidrio","viejo","viernes","vigor","vil","villa","vinagre","vino","viñedo","violín","viral","virgo","virtud","visor","víspera","vista","vitamina","viudo","vivaz","vivero","vivir","vivo","volcán","volumen","volver","voraz","votar","voto","voz","vuelo","vulgar","yacer","yate","yegua","yema","yerno","yeso","yodo","yoga","yogur","zafiro","zanja","zapato","zarza","zona","zorro","zumo","zurdo"]');
const require$$7 = /* @__PURE__ */ JSON.parse('["あいこくしん","あいさつ","あいだ","あおぞら","あかちゃん","あきる","あけがた","あける","あこがれる","あさい","あさひ","あしあと","あじわう","あずかる","あずき","あそぶ","あたえる","あたためる","あたりまえ","あたる","あつい","あつかう","あっしゅく","あつまり","あつめる","あてな","あてはまる","あひる","あぶら","あぶる","あふれる","あまい","あまど","あまやかす","あまり","あみもの","あめりか","あやまる","あゆむ","あらいぐま","あらし","あらすじ","あらためる","あらゆる","あらわす","ありがとう","あわせる","あわてる","あんい","あんがい","あんこ","あんぜん","あんてい","あんない","あんまり","いいだす","いおん","いがい","いがく","いきおい","いきなり","いきもの","いきる","いくじ","いくぶん","いけばな","いけん","いこう","いこく","いこつ","いさましい","いさん","いしき","いじゅう","いじょう","いじわる","いずみ","いずれ","いせい","いせえび","いせかい","いせき","いぜん","いそうろう","いそがしい","いだい","いだく","いたずら","いたみ","いたりあ","いちおう","いちじ","いちど","いちば","いちぶ","いちりゅう","いつか","いっしゅん","いっせい","いっそう","いったん","いっち","いってい","いっぽう","いてざ","いてん","いどう","いとこ","いない","いなか","いねむり","いのち","いのる","いはつ","いばる","いはん","いびき","いひん","いふく","いへん","いほう","いみん","いもうと","いもたれ","いもり","いやがる","いやす","いよかん","いよく","いらい","いらすと","いりぐち","いりょう","いれい","いれもの","いれる","いろえんぴつ","いわい","いわう","いわかん","いわば","いわゆる","いんげんまめ","いんさつ","いんしょう","いんよう","うえき","うえる","うおざ","うがい","うかぶ","うかべる","うきわ","うくらいな","うくれれ","うけたまわる","うけつけ","うけとる","うけもつ","うける","うごかす","うごく","うこん","うさぎ","うしなう","うしろがみ","うすい","うすぎ","うすぐらい","うすめる","うせつ","うちあわせ","うちがわ","うちき","うちゅう","うっかり","うつくしい","うったえる","うつる","うどん","うなぎ","うなじ","うなずく","うなる","うねる","うのう","うぶげ","うぶごえ","うまれる","うめる","うもう","うやまう","うよく","うらがえす","うらぐち","うらない","うりあげ","うりきれ","うるさい","うれしい","うれゆき","うれる","うろこ","うわき","うわさ","うんこう","うんちん","うんてん","うんどう","えいえん","えいが","えいきょう","えいご","えいせい","えいぶん","えいよう","えいわ","えおり","えがお","えがく","えきたい","えくせる","えしゃく","えすて","えつらん","えのぐ","えほうまき","えほん","えまき","えもじ","えもの","えらい","えらぶ","えりあ","えんえん","えんかい","えんぎ","えんげき","えんしゅう","えんぜつ","えんそく","えんちょう","えんとつ","おいかける","おいこす","おいしい","おいつく","おうえん","おうさま","おうじ","おうせつ","おうたい","おうふく","おうべい","おうよう","おえる","おおい","おおう","おおどおり","おおや","おおよそ","おかえり","おかず","おがむ","おかわり","おぎなう","おきる","おくさま","おくじょう","おくりがな","おくる","おくれる","おこす","おこなう","おこる","おさえる","おさない","おさめる","おしいれ","おしえる","おじぎ","おじさん","おしゃれ","おそらく","おそわる","おたがい","おたく","おだやか","おちつく","おっと","おつり","おでかけ","おとしもの","おとなしい","おどり","おどろかす","おばさん","おまいり","おめでとう","おもいで","おもう","おもたい","おもちゃ","おやつ","おやゆび","およぼす","おらんだ","おろす","おんがく","おんけい","おんしゃ","おんせん","おんだん","おんちゅう","おんどけい","かあつ","かいが","がいき","がいけん","がいこう","かいさつ","かいしゃ","かいすいよく","かいぜん","かいぞうど","かいつう","かいてん","かいとう","かいふく","がいへき","かいほう","かいよう","がいらい","かいわ","かえる","かおり","かかえる","かがく","かがし","かがみ","かくご","かくとく","かざる","がぞう","かたい","かたち","がちょう","がっきゅう","がっこう","がっさん","がっしょう","かなざわし","かのう","がはく","かぶか","かほう","かほご","かまう","かまぼこ","かめれおん","かゆい","かようび","からい","かるい","かろう","かわく","かわら","がんか","かんけい","かんこう","かんしゃ","かんそう","かんたん","かんち","がんばる","きあい","きあつ","きいろ","ぎいん","きうい","きうん","きえる","きおう","きおく","きおち","きおん","きかい","きかく","きかんしゃ","ききて","きくばり","きくらげ","きけんせい","きこう","きこえる","きこく","きさい","きさく","きさま","きさらぎ","ぎじかがく","ぎしき","ぎじたいけん","ぎじにってい","ぎじゅつしゃ","きすう","きせい","きせき","きせつ","きそう","きぞく","きぞん","きたえる","きちょう","きつえん","ぎっちり","きつつき","きつね","きてい","きどう","きどく","きない","きなが","きなこ","きぬごし","きねん","きのう","きのした","きはく","きびしい","きひん","きふく","きぶん","きぼう","きほん","きまる","きみつ","きむずかしい","きめる","きもだめし","きもち","きもの","きゃく","きやく","ぎゅうにく","きよう","きょうりゅう","きらい","きらく","きりん","きれい","きれつ","きろく","ぎろん","きわめる","ぎんいろ","きんかくじ","きんじょ","きんようび","ぐあい","くいず","くうかん","くうき","くうぐん","くうこう","ぐうせい","くうそう","ぐうたら","くうふく","くうぼ","くかん","くきょう","くげん","ぐこう","くさい","くさき","くさばな","くさる","くしゃみ","くしょう","くすのき","くすりゆび","くせげ","くせん","ぐたいてき","くださる","くたびれる","くちこみ","くちさき","くつした","ぐっすり","くつろぐ","くとうてん","くどく","くなん","くねくね","くのう","くふう","くみあわせ","くみたてる","くめる","くやくしょ","くらす","くらべる","くるま","くれる","くろう","くわしい","ぐんかん","ぐんしょく","ぐんたい","ぐんて","けあな","けいかく","けいけん","けいこ","けいさつ","げいじゅつ","けいたい","げいのうじん","けいれき","けいろ","けおとす","けおりもの","げきか","げきげん","げきだん","げきちん","げきとつ","げきは","げきやく","げこう","げこくじょう","げざい","けさき","げざん","けしき","けしごむ","けしょう","げすと","けたば","けちゃっぷ","けちらす","けつあつ","けつい","けつえき","けっこん","けつじょ","けっせき","けってい","けつまつ","げつようび","げつれい","けつろん","げどく","けとばす","けとる","けなげ","けなす","けなみ","けぬき","げねつ","けねん","けはい","げひん","けぶかい","げぼく","けまり","けみかる","けむし","けむり","けもの","けらい","けろけろ","けわしい","けんい","けんえつ","けんお","けんか","げんき","けんげん","けんこう","けんさく","けんしゅう","けんすう","げんそう","けんちく","けんてい","けんとう","けんない","けんにん","げんぶつ","けんま","けんみん","けんめい","けんらん","けんり","こあくま","こいぬ","こいびと","ごうい","こうえん","こうおん","こうかん","ごうきゅう","ごうけい","こうこう","こうさい","こうじ","こうすい","ごうせい","こうそく","こうたい","こうちゃ","こうつう","こうてい","こうどう","こうない","こうはい","ごうほう","ごうまん","こうもく","こうりつ","こえる","こおり","ごかい","ごがつ","ごかん","こくご","こくさい","こくとう","こくない","こくはく","こぐま","こけい","こける","ここのか","こころ","こさめ","こしつ","こすう","こせい","こせき","こぜん","こそだて","こたい","こたえる","こたつ","こちょう","こっか","こつこつ","こつばん","こつぶ","こてい","こてん","ことがら","ことし","ことば","ことり","こなごな","こねこね","このまま","このみ","このよ","ごはん","こひつじ","こふう","こふん","こぼれる","ごまあぶら","こまかい","ごますり","こまつな","こまる","こむぎこ","こもじ","こもち","こもの","こもん","こやく","こやま","こゆう","こゆび","こよい","こよう","こりる","これくしょん","ころっけ","こわもて","こわれる","こんいん","こんかい","こんき","こんしゅう","こんすい","こんだて","こんとん","こんなん","こんびに","こんぽん","こんまけ","こんや","こんれい","こんわく","ざいえき","さいかい","さいきん","ざいげん","ざいこ","さいしょ","さいせい","ざいたく","ざいちゅう","さいてき","ざいりょう","さうな","さかいし","さがす","さかな","さかみち","さがる","さぎょう","さくし","さくひん","さくら","さこく","さこつ","さずかる","ざせき","さたん","さつえい","ざつおん","ざっか","ざつがく","さっきょく","ざっし","さつじん","ざっそう","さつたば","さつまいも","さてい","さといも","さとう","さとおや","さとし","さとる","さのう","さばく","さびしい","さべつ","さほう","さほど","さます","さみしい","さみだれ","さむけ","さめる","さやえんどう","さゆう","さよう","さよく","さらだ","ざるそば","さわやか","さわる","さんいん","さんか","さんきゃく","さんこう","さんさい","ざんしょ","さんすう","さんせい","さんそ","さんち","さんま","さんみ","さんらん","しあい","しあげ","しあさって","しあわせ","しいく","しいん","しうち","しえい","しおけ","しかい","しかく","じかん","しごと","しすう","じだい","したうけ","したぎ","したて","したみ","しちょう","しちりん","しっかり","しつじ","しつもん","してい","してき","してつ","じてん","じどう","しなぎれ","しなもの","しなん","しねま","しねん","しのぐ","しのぶ","しはい","しばかり","しはつ","しはらい","しはん","しひょう","しふく","じぶん","しへい","しほう","しほん","しまう","しまる","しみん","しむける","じむしょ","しめい","しめる","しもん","しゃいん","しゃうん","しゃおん","じゃがいも","しやくしょ","しゃくほう","しゃけん","しゃこ","しゃざい","しゃしん","しゃせん","しゃそう","しゃたい","しゃちょう","しゃっきん","じゃま","しゃりん","しゃれい","じゆう","じゅうしょ","しゅくはく","じゅしん","しゅっせき","しゅみ","しゅらば","じゅんばん","しょうかい","しょくたく","しょっけん","しょどう","しょもつ","しらせる","しらべる","しんか","しんこう","じんじゃ","しんせいじ","しんちく","しんりん","すあげ","すあし","すあな","ずあん","すいえい","すいか","すいとう","ずいぶん","すいようび","すうがく","すうじつ","すうせん","すおどり","すきま","すくう","すくない","すける","すごい","すこし","ずさん","すずしい","すすむ","すすめる","すっかり","ずっしり","ずっと","すてき","すてる","すねる","すのこ","すはだ","すばらしい","ずひょう","ずぶぬれ","すぶり","すふれ","すべて","すべる","ずほう","すぼん","すまい","すめし","すもう","すやき","すらすら","するめ","すれちがう","すろっと","すわる","すんぜん","すんぽう","せあぶら","せいかつ","せいげん","せいじ","せいよう","せおう","せかいかん","せきにん","せきむ","せきゆ","せきらんうん","せけん","せこう","せすじ","せたい","せたけ","せっかく","せっきゃく","ぜっく","せっけん","せっこつ","せっさたくま","せつぞく","せつだん","せつでん","せっぱん","せつび","せつぶん","せつめい","せつりつ","せなか","せのび","せはば","せびろ","せぼね","せまい","せまる","せめる","せもたれ","せりふ","ぜんあく","せんい","せんえい","せんか","せんきょ","せんく","せんげん","ぜんご","せんさい","せんしゅ","せんすい","せんせい","せんぞ","せんたく","せんちょう","せんてい","せんとう","せんぬき","せんねん","せんぱい","ぜんぶ","ぜんぽう","せんむ","せんめんじょ","せんもん","せんやく","せんゆう","せんよう","ぜんら","ぜんりゃく","せんれい","せんろ","そあく","そいとげる","そいね","そうがんきょう","そうき","そうご","そうしん","そうだん","そうなん","そうび","そうめん","そうり","そえもの","そえん","そがい","そげき","そこう","そこそこ","そざい","そしな","そせい","そせん","そそぐ","そだてる","そつう","そつえん","そっかん","そつぎょう","そっけつ","そっこう","そっせん","そっと","そとがわ","そとづら","そなえる","そなた","そふぼ","そぼく","そぼろ","そまつ","そまる","そむく","そむりえ","そめる","そもそも","そよかぜ","そらまめ","そろう","そんかい","そんけい","そんざい","そんしつ","そんぞく","そんちょう","ぞんび","ぞんぶん","そんみん","たあい","たいいん","たいうん","たいえき","たいおう","だいがく","たいき","たいぐう","たいけん","たいこ","たいざい","だいじょうぶ","だいすき","たいせつ","たいそう","だいたい","たいちょう","たいてい","だいどころ","たいない","たいねつ","たいのう","たいはん","だいひょう","たいふう","たいへん","たいほ","たいまつばな","たいみんぐ","たいむ","たいめん","たいやき","たいよう","たいら","たいりょく","たいる","たいわん","たうえ","たえる","たおす","たおる","たおれる","たかい","たかね","たきび","たくさん","たこく","たこやき","たさい","たしざん","だじゃれ","たすける","たずさわる","たそがれ","たたかう","たたく","ただしい","たたみ","たちばな","だっかい","だっきゃく","だっこ","だっしゅつ","だったい","たてる","たとえる","たなばた","たにん","たぬき","たのしみ","たはつ","たぶん","たべる","たぼう","たまご","たまる","だむる","ためいき","ためす","ためる","たもつ","たやすい","たよる","たらす","たりきほんがん","たりょう","たりる","たると","たれる","たれんと","たろっと","たわむれる","だんあつ","たんい","たんおん","たんか","たんき","たんけん","たんご","たんさん","たんじょうび","だんせい","たんそく","たんたい","だんち","たんてい","たんとう","だんな","たんにん","だんねつ","たんのう","たんぴん","だんぼう","たんまつ","たんめい","だんれつ","だんろ","だんわ","ちあい","ちあん","ちいき","ちいさい","ちえん","ちかい","ちから","ちきゅう","ちきん","ちけいず","ちけん","ちこく","ちさい","ちしき","ちしりょう","ちせい","ちそう","ちたい","ちたん","ちちおや","ちつじょ","ちてき","ちてん","ちぬき","ちぬり","ちのう","ちひょう","ちへいせん","ちほう","ちまた","ちみつ","ちみどろ","ちめいど","ちゃんこなべ","ちゅうい","ちゆりょく","ちょうし","ちょさくけん","ちらし","ちらみ","ちりがみ","ちりょう","ちるど","ちわわ","ちんたい","ちんもく","ついか","ついたち","つうか","つうじょう","つうはん","つうわ","つかう","つかれる","つくね","つくる","つけね","つける","つごう","つたえる","つづく","つつじ","つつむ","つとめる","つながる","つなみ","つねづね","つのる","つぶす","つまらない","つまる","つみき","つめたい","つもり","つもる","つよい","つるぼ","つるみく","つわもの","つわり","てあし","てあて","てあみ","ていおん","ていか","ていき","ていけい","ていこく","ていさつ","ていし","ていせい","ていたい","ていど","ていねい","ていひょう","ていへん","ていぼう","てうち","ておくれ","てきとう","てくび","でこぼこ","てさぎょう","てさげ","てすり","てそう","てちがい","てちょう","てつがく","てつづき","でっぱ","てつぼう","てつや","でぬかえ","てぬき","てぬぐい","てのひら","てはい","てぶくろ","てふだ","てほどき","てほん","てまえ","てまきずし","てみじか","てみやげ","てらす","てれび","てわけ","てわたし","でんあつ","てんいん","てんかい","てんき","てんぐ","てんけん","てんごく","てんさい","てんし","てんすう","でんち","てんてき","てんとう","てんない","てんぷら","てんぼうだい","てんめつ","てんらんかい","でんりょく","でんわ","どあい","といれ","どうかん","とうきゅう","どうぐ","とうし","とうむぎ","とおい","とおか","とおく","とおす","とおる","とかい","とかす","ときおり","ときどき","とくい","とくしゅう","とくてん","とくに","とくべつ","とけい","とける","とこや","とさか","としょかん","とそう","とたん","とちゅう","とっきゅう","とっくん","とつぜん","とつにゅう","とどける","ととのえる","とない","となえる","となり","とのさま","とばす","どぶがわ","とほう","とまる","とめる","ともだち","ともる","どようび","とらえる","とんかつ","どんぶり","ないかく","ないこう","ないしょ","ないす","ないせん","ないそう","なおす","ながい","なくす","なげる","なこうど","なさけ","なたでここ","なっとう","なつやすみ","ななおし","なにごと","なにもの","なにわ","なのか","なふだ","なまいき","なまえ","なまみ","なみだ","なめらか","なめる","なやむ","ならう","ならび","ならぶ","なれる","なわとび","なわばり","にあう","にいがた","にうけ","におい","にかい","にがて","にきび","にくしみ","にくまん","にげる","にさんかたんそ","にしき","にせもの","にちじょう","にちようび","にっか","にっき","にっけい","にっこう","にっさん","にっしょく","にっすう","にっせき","にってい","になう","にほん","にまめ","にもつ","にやり","にゅういん","にりんしゃ","にわとり","にんい","にんか","にんき","にんげん","にんしき","にんずう","にんそう","にんたい","にんち","にんてい","にんにく","にんぷ","にんまり","にんむ","にんめい","にんよう","ぬいくぎ","ぬかす","ぬぐいとる","ぬぐう","ぬくもり","ぬすむ","ぬまえび","ぬめり","ぬらす","ぬんちゃく","ねあげ","ねいき","ねいる","ねいろ","ねぐせ","ねくたい","ねくら","ねこぜ","ねこむ","ねさげ","ねすごす","ねそべる","ねだん","ねつい","ねっしん","ねつぞう","ねったいぎょ","ねぶそく","ねふだ","ねぼう","ねほりはほり","ねまき","ねまわし","ねみみ","ねむい","ねむたい","ねもと","ねらう","ねわざ","ねんいり","ねんおし","ねんかん","ねんきん","ねんぐ","ねんざ","ねんし","ねんちゃく","ねんど","ねんぴ","ねんぶつ","ねんまつ","ねんりょう","ねんれい","のいず","のおづま","のがす","のきなみ","のこぎり","のこす","のこる","のせる","のぞく","のぞむ","のたまう","のちほど","のっく","のばす","のはら","のべる","のぼる","のみもの","のやま","のらいぬ","のらねこ","のりもの","のりゆき","のれん","のんき","ばあい","はあく","ばあさん","ばいか","ばいく","はいけん","はいご","はいしん","はいすい","はいせん","はいそう","はいち","ばいばい","はいれつ","はえる","はおる","はかい","ばかり","はかる","はくしゅ","はけん","はこぶ","はさみ","はさん","はしご","ばしょ","はしる","はせる","ぱそこん","はそん","はたん","はちみつ","はつおん","はっかく","はづき","はっきり","はっくつ","はっけん","はっこう","はっさん","はっしん","はったつ","はっちゅう","はってん","はっぴょう","はっぽう","はなす","はなび","はにかむ","はぶらし","はみがき","はむかう","はめつ","はやい","はやし","はらう","はろうぃん","はわい","はんい","はんえい","はんおん","はんかく","はんきょう","ばんぐみ","はんこ","はんしゃ","はんすう","はんだん","ぱんち","ぱんつ","はんてい","はんとし","はんのう","はんぱ","はんぶん","はんぺん","はんぼうき","はんめい","はんらん","はんろん","ひいき","ひうん","ひえる","ひかく","ひかり","ひかる","ひかん","ひくい","ひけつ","ひこうき","ひこく","ひさい","ひさしぶり","ひさん","びじゅつかん","ひしょ","ひそか","ひそむ","ひたむき","ひだり","ひたる","ひつぎ","ひっこし","ひっし","ひつじゅひん","ひっす","ひつぜん","ぴったり","ぴっちり","ひつよう","ひてい","ひとごみ","ひなまつり","ひなん","ひねる","ひはん","ひびく","ひひょう","ひほう","ひまわり","ひまん","ひみつ","ひめい","ひめじし","ひやけ","ひやす","ひよう","びょうき","ひらがな","ひらく","ひりつ","ひりょう","ひるま","ひるやすみ","ひれい","ひろい","ひろう","ひろき","ひろゆき","ひんかく","ひんけつ","ひんこん","ひんしゅ","ひんそう","ぴんち","ひんぱん","びんぼう","ふあん","ふいうち","ふうけい","ふうせん","ぷうたろう","ふうとう","ふうふ","ふえる","ふおん","ふかい","ふきん","ふくざつ","ふくぶくろ","ふこう","ふさい","ふしぎ","ふじみ","ふすま","ふせい","ふせぐ","ふそく","ぶたにく","ふたん","ふちょう","ふつう","ふつか","ふっかつ","ふっき","ふっこく","ぶどう","ふとる","ふとん","ふのう","ふはい","ふひょう","ふへん","ふまん","ふみん","ふめつ","ふめん","ふよう","ふりこ","ふりる","ふるい","ふんいき","ぶんがく","ぶんぐ","ふんしつ","ぶんせき","ふんそう","ぶんぽう","へいあん","へいおん","へいがい","へいき","へいげん","へいこう","へいさ","へいしゃ","へいせつ","へいそ","へいたく","へいてん","へいねつ","へいわ","へきが","へこむ","べにいろ","べにしょうが","へらす","へんかん","べんきょう","べんごし","へんさい","へんたい","べんり","ほあん","ほいく","ぼうぎょ","ほうこく","ほうそう","ほうほう","ほうもん","ほうりつ","ほえる","ほおん","ほかん","ほきょう","ぼきん","ほくろ","ほけつ","ほけん","ほこう","ほこる","ほしい","ほしつ","ほしゅ","ほしょう","ほせい","ほそい","ほそく","ほたて","ほたる","ぽちぶくろ","ほっきょく","ほっさ","ほったん","ほとんど","ほめる","ほんい","ほんき","ほんけ","ほんしつ","ほんやく","まいにち","まかい","まかせる","まがる","まける","まこと","まさつ","まじめ","ますく","まぜる","まつり","まとめ","まなぶ","まぬけ","まねく","まほう","まもる","まゆげ","まよう","まろやか","まわす","まわり","まわる","まんが","まんきつ","まんぞく","まんなか","みいら","みうち","みえる","みがく","みかた","みかん","みけん","みこん","みじかい","みすい","みすえる","みせる","みっか","みつかる","みつける","みてい","みとめる","みなと","みなみかさい","みねらる","みのう","みのがす","みほん","みもと","みやげ","みらい","みりょく","みわく","みんか","みんぞく","むいか","むえき","むえん","むかい","むかう","むかえ","むかし","むぎちゃ","むける","むげん","むさぼる","むしあつい","むしば","むじゅん","むしろ","むすう","むすこ","むすぶ","むすめ","むせる","むせん","むちゅう","むなしい","むのう","むやみ","むよう","むらさき","むりょう","むろん","めいあん","めいうん","めいえん","めいかく","めいきょく","めいさい","めいし","めいそう","めいぶつ","めいれい","めいわく","めぐまれる","めざす","めした","めずらしい","めだつ","めまい","めやす","めんきょ","めんせき","めんどう","もうしあげる","もうどうけん","もえる","もくし","もくてき","もくようび","もちろん","もどる","もらう","もんく","もんだい","やおや","やける","やさい","やさしい","やすい","やすたろう","やすみ","やせる","やそう","やたい","やちん","やっと","やっぱり","やぶる","やめる","ややこしい","やよい","やわらかい","ゆうき","ゆうびんきょく","ゆうべ","ゆうめい","ゆけつ","ゆしゅつ","ゆせん","ゆそう","ゆたか","ゆちゃく","ゆでる","ゆにゅう","ゆびわ","ゆらい","ゆれる","ようい","ようか","ようきゅう","ようじ","ようす","ようちえん","よかぜ","よかん","よきん","よくせい","よくぼう","よけい","よごれる","よさん","よしゅう","よそう","よそく","よっか","よてい","よどがわく","よねつ","よやく","よゆう","よろこぶ","よろしい","らいう","らくがき","らくご","らくさつ","らくだ","らしんばん","らせん","らぞく","らたい","らっか","られつ","りえき","りかい","りきさく","りきせつ","りくぐん","りくつ","りけん","りこう","りせい","りそう","りそく","りてん","りねん","りゆう","りゅうがく","りよう","りょうり","りょかん","りょくちゃ","りょこう","りりく","りれき","りろん","りんご","るいけい","るいさい","るいじ","るいせき","るすばん","るりがわら","れいかん","れいぎ","れいせい","れいぞうこ","れいとう","れいぼう","れきし","れきだい","れんあい","れんけい","れんこん","れんさい","れんしゅう","れんぞく","れんらく","ろうか","ろうご","ろうじん","ろうそく","ろくが","ろこつ","ろじうら","ろしゅつ","ろせん","ろてん","ろめん","ろれつ","ろんぎ","ろんぱ","ろんぶん","ろんり","わかす","わかめ","わかやま","わかれる","わしつ","わじまし","わすれもの","わらう","われる"]');
const require$$8 = /* @__PURE__ */ JSON.parse('["abacate","abaixo","abalar","abater","abduzir","abelha","aberto","abismo","abotoar","abranger","abreviar","abrigar","abrupto","absinto","absoluto","absurdo","abutre","acabado","acalmar","acampar","acanhar","acaso","aceitar","acelerar","acenar","acervo","acessar","acetona","achatar","acidez","acima","acionado","acirrar","aclamar","aclive","acolhida","acomodar","acoplar","acordar","acumular","acusador","adaptar","adega","adentro","adepto","adequar","aderente","adesivo","adeus","adiante","aditivo","adjetivo","adjunto","admirar","adorar","adquirir","adubo","adverso","advogado","aeronave","afastar","aferir","afetivo","afinador","afivelar","aflito","afluente","afrontar","agachar","agarrar","agasalho","agenciar","agilizar","agiota","agitado","agora","agradar","agreste","agrupar","aguardar","agulha","ajoelhar","ajudar","ajustar","alameda","alarme","alastrar","alavanca","albergue","albino","alcatra","aldeia","alecrim","alegria","alertar","alface","alfinete","algum","alheio","aliar","alicate","alienar","alinhar","aliviar","almofada","alocar","alpiste","alterar","altitude","alucinar","alugar","aluno","alusivo","alvo","amaciar","amador","amarelo","amassar","ambas","ambiente","ameixa","amenizar","amido","amistoso","amizade","amolador","amontoar","amoroso","amostra","amparar","ampliar","ampola","anagrama","analisar","anarquia","anatomia","andaime","anel","anexo","angular","animar","anjo","anomalia","anotado","ansioso","anterior","anuidade","anunciar","anzol","apagador","apalpar","apanhado","apego","apelido","apertada","apesar","apetite","apito","aplauso","aplicada","apoio","apontar","aposta","aprendiz","aprovar","aquecer","arame","aranha","arara","arcada","ardente","areia","arejar","arenito","aresta","argiloso","argola","arma","arquivo","arraial","arrebate","arriscar","arroba","arrumar","arsenal","arterial","artigo","arvoredo","asfaltar","asilado","aspirar","assador","assinar","assoalho","assunto","astral","atacado","atadura","atalho","atarefar","atear","atender","aterro","ateu","atingir","atirador","ativo","atoleiro","atracar","atrevido","atriz","atual","atum","auditor","aumentar","aura","aurora","autismo","autoria","autuar","avaliar","avante","avaria","avental","avesso","aviador","avisar","avulso","axila","azarar","azedo","azeite","azulejo","babar","babosa","bacalhau","bacharel","bacia","bagagem","baiano","bailar","baioneta","bairro","baixista","bajular","baleia","baliza","balsa","banal","bandeira","banho","banir","banquete","barato","barbado","baronesa","barraca","barulho","baseado","bastante","batata","batedor","batida","batom","batucar","baunilha","beber","beijo","beirada","beisebol","beldade","beleza","belga","beliscar","bendito","bengala","benzer","berimbau","berlinda","berro","besouro","bexiga","bezerro","bico","bicudo","bienal","bifocal","bifurcar","bigorna","bilhete","bimestre","bimotor","biologia","biombo","biosfera","bipolar","birrento","biscoito","bisneto","bispo","bissexto","bitola","bizarro","blindado","bloco","bloquear","boato","bobagem","bocado","bocejo","bochecha","boicotar","bolada","boletim","bolha","bolo","bombeiro","bonde","boneco","bonita","borbulha","borda","boreal","borracha","bovino","boxeador","branco","brasa","braveza","breu","briga","brilho","brincar","broa","brochura","bronzear","broto","bruxo","bucha","budismo","bufar","bule","buraco","busca","busto","buzina","cabana","cabelo","cabide","cabo","cabrito","cacau","cacetada","cachorro","cacique","cadastro","cadeado","cafezal","caiaque","caipira","caixote","cajado","caju","calafrio","calcular","caldeira","calibrar","calmante","calota","camada","cambista","camisa","camomila","campanha","camuflar","canavial","cancelar","caneta","canguru","canhoto","canivete","canoa","cansado","cantar","canudo","capacho","capela","capinar","capotar","capricho","captador","capuz","caracol","carbono","cardeal","careca","carimbar","carneiro","carpete","carreira","cartaz","carvalho","casaco","casca","casebre","castelo","casulo","catarata","cativar","caule","causador","cautelar","cavalo","caverna","cebola","cedilha","cegonha","celebrar","celular","cenoura","censo","centeio","cercar","cerrado","certeiro","cerveja","cetim","cevada","chacota","chaleira","chamado","chapada","charme","chatice","chave","chefe","chegada","cheiro","cheque","chicote","chifre","chinelo","chocalho","chover","chumbo","chutar","chuva","cicatriz","ciclone","cidade","cidreira","ciente","cigana","cimento","cinto","cinza","ciranda","circuito","cirurgia","citar","clareza","clero","clicar","clone","clube","coado","coagir","cobaia","cobertor","cobrar","cocada","coelho","coentro","coeso","cogumelo","coibir","coifa","coiote","colar","coleira","colher","colidir","colmeia","colono","coluna","comando","combinar","comentar","comitiva","comover","complexo","comum","concha","condor","conectar","confuso","congelar","conhecer","conjugar","consumir","contrato","convite","cooperar","copeiro","copiador","copo","coquetel","coragem","cordial","corneta","coronha","corporal","correio","cortejo","coruja","corvo","cosseno","costela","cotonete","couro","couve","covil","cozinha","cratera","cravo","creche","credor","creme","crer","crespo","criada","criminal","crioulo","crise","criticar","crosta","crua","cruzeiro","cubano","cueca","cuidado","cujo","culatra","culminar","culpar","cultura","cumprir","cunhado","cupido","curativo","curral","cursar","curto","cuspir","custear","cutelo","damasco","datar","debater","debitar","deboche","debulhar","decalque","decimal","declive","decote","decretar","dedal","dedicado","deduzir","defesa","defumar","degelo","degrau","degustar","deitado","deixar","delator","delegado","delinear","delonga","demanda","demitir","demolido","dentista","depenado","depilar","depois","depressa","depurar","deriva","derramar","desafio","desbotar","descanso","desenho","desfiado","desgaste","desigual","deslize","desmamar","desova","despesa","destaque","desviar","detalhar","detentor","detonar","detrito","deusa","dever","devido","devotado","dezena","diagrama","dialeto","didata","difuso","digitar","dilatado","diluente","diminuir","dinastia","dinheiro","diocese","direto","discreta","disfarce","disparo","disquete","dissipar","distante","ditador","diurno","diverso","divisor","divulgar","dizer","dobrador","dolorido","domador","dominado","donativo","donzela","dormente","dorsal","dosagem","dourado","doutor","drenagem","drible","drogaria","duelar","duende","dueto","duplo","duquesa","durante","duvidoso","eclodir","ecoar","ecologia","edificar","edital","educado","efeito","efetivar","ejetar","elaborar","eleger","eleitor","elenco","elevador","eliminar","elogiar","embargo","embolado","embrulho","embutido","emenda","emergir","emissor","empatia","empenho","empinado","empolgar","emprego","empurrar","emulador","encaixe","encenado","enchente","encontro","endeusar","endossar","enfaixar","enfeite","enfim","engajado","engenho","englobar","engomado","engraxar","enguia","enjoar","enlatar","enquanto","enraizar","enrolado","enrugar","ensaio","enseada","ensino","ensopado","entanto","enteado","entidade","entortar","entrada","entulho","envergar","enviado","envolver","enxame","enxerto","enxofre","enxuto","epiderme","equipar","ereto","erguido","errata","erva","ervilha","esbanjar","esbelto","escama","escola","escrita","escuta","esfinge","esfolar","esfregar","esfumado","esgrima","esmalte","espanto","espelho","espiga","esponja","espreita","espumar","esquerda","estaca","esteira","esticar","estofado","estrela","estudo","esvaziar","etanol","etiqueta","euforia","europeu","evacuar","evaporar","evasivo","eventual","evidente","evoluir","exagero","exalar","examinar","exato","exausto","excesso","excitar","exclamar","executar","exemplo","exibir","exigente","exonerar","expandir","expelir","expirar","explanar","exposto","expresso","expulsar","externo","extinto","extrato","fabricar","fabuloso","faceta","facial","fada","fadiga","faixa","falar","falta","familiar","fandango","fanfarra","fantoche","fardado","farelo","farinha","farofa","farpa","fartura","fatia","fator","favorita","faxina","fazenda","fechado","feijoada","feirante","felino","feminino","fenda","feno","fera","feriado","ferrugem","ferver","festejar","fetal","feudal","fiapo","fibrose","ficar","ficheiro","figurado","fileira","filho","filme","filtrar","firmeza","fisgada","fissura","fita","fivela","fixador","fixo","flacidez","flamingo","flanela","flechada","flora","flutuar","fluxo","focal","focinho","fofocar","fogo","foguete","foice","folgado","folheto","forjar","formiga","forno","forte","fosco","fossa","fragata","fralda","frango","frasco","fraterno","freira","frente","fretar","frieza","friso","fritura","fronha","frustrar","fruteira","fugir","fulano","fuligem","fundar","fungo","funil","furador","furioso","futebol","gabarito","gabinete","gado","gaiato","gaiola","gaivota","galega","galho","galinha","galocha","ganhar","garagem","garfo","gargalo","garimpo","garoupa","garrafa","gasoduto","gasto","gata","gatilho","gaveta","gazela","gelado","geleia","gelo","gemada","gemer","gemido","generoso","gengiva","genial","genoma","genro","geologia","gerador","germinar","gesso","gestor","ginasta","gincana","gingado","girafa","girino","glacial","glicose","global","glorioso","goela","goiaba","golfe","golpear","gordura","gorjeta","gorro","gostoso","goteira","governar","gracejo","gradual","grafite","gralha","grampo","granada","gratuito","graveto","graxa","grego","grelhar","greve","grilo","grisalho","gritaria","grosso","grotesco","grudado","grunhido","gruta","guache","guarani","guaxinim","guerrear","guiar","guincho","guisado","gula","guloso","guru","habitar","harmonia","haste","haver","hectare","herdar","heresia","hesitar","hiato","hibernar","hidratar","hiena","hino","hipismo","hipnose","hipoteca","hoje","holofote","homem","honesto","honrado","hormonal","hospedar","humorado","iate","ideia","idoso","ignorado","igreja","iguana","ileso","ilha","iludido","iluminar","ilustrar","imagem","imediato","imenso","imersivo","iminente","imitador","imortal","impacto","impedir","implante","impor","imprensa","impune","imunizar","inalador","inapto","inativo","incenso","inchar","incidir","incluir","incolor","indeciso","indireto","indutor","ineficaz","inerente","infantil","infestar","infinito","inflamar","informal","infrator","ingerir","inibido","inicial","inimigo","injetar","inocente","inodoro","inovador","inox","inquieto","inscrito","inseto","insistir","inspetor","instalar","insulto","intacto","integral","intimar","intocado","intriga","invasor","inverno","invicto","invocar","iogurte","iraniano","ironizar","irreal","irritado","isca","isento","isolado","isqueiro","italiano","janeiro","jangada","janta","jararaca","jardim","jarro","jasmim","jato","javali","jazida","jejum","joaninha","joelhada","jogador","joia","jornal","jorrar","jovem","juba","judeu","judoca","juiz","julgador","julho","jurado","jurista","juro","justa","labareda","laboral","lacre","lactante","ladrilho","lagarta","lagoa","laje","lamber","lamentar","laminar","lampejo","lanche","lapidar","lapso","laranja","lareira","largura","lasanha","lastro","lateral","latido","lavanda","lavoura","lavrador","laxante","lazer","lealdade","lebre","legado","legendar","legista","leigo","leiloar","leitura","lembrete","leme","lenhador","lentilha","leoa","lesma","leste","letivo","letreiro","levar","leveza","levitar","liberal","libido","liderar","ligar","ligeiro","limitar","limoeiro","limpador","linda","linear","linhagem","liquidez","listagem","lisura","litoral","livro","lixa","lixeira","locador","locutor","lojista","lombo","lona","longe","lontra","lorde","lotado","loteria","loucura","lousa","louvar","luar","lucidez","lucro","luneta","lustre","lutador","luva","macaco","macete","machado","macio","madeira","madrinha","magnata","magreza","maior","mais","malandro","malha","malote","maluco","mamilo","mamoeiro","mamute","manada","mancha","mandato","manequim","manhoso","manivela","manobrar","mansa","manter","manusear","mapeado","maquinar","marcador","maresia","marfim","margem","marinho","marmita","maroto","marquise","marreco","martelo","marujo","mascote","masmorra","massagem","mastigar","matagal","materno","matinal","matutar","maxilar","medalha","medida","medusa","megafone","meiga","melancia","melhor","membro","memorial","menino","menos","mensagem","mental","merecer","mergulho","mesada","mesclar","mesmo","mesquita","mestre","metade","meteoro","metragem","mexer","mexicano","micro","migalha","migrar","milagre","milenar","milhar","mimado","minerar","minhoca","ministro","minoria","miolo","mirante","mirtilo","misturar","mocidade","moderno","modular","moeda","moer","moinho","moita","moldura","moleza","molho","molinete","molusco","montanha","moqueca","morango","morcego","mordomo","morena","mosaico","mosquete","mostarda","motel","motim","moto","motriz","muda","muito","mulata","mulher","multar","mundial","munido","muralha","murcho","muscular","museu","musical","nacional","nadador","naja","namoro","narina","narrado","nascer","nativa","natureza","navalha","navegar","navio","neblina","nebuloso","negativa","negociar","negrito","nervoso","neta","neural","nevasca","nevoeiro","ninar","ninho","nitidez","nivelar","nobreza","noite","noiva","nomear","nominal","nordeste","nortear","notar","noticiar","noturno","novelo","novilho","novo","nublado","nudez","numeral","nupcial","nutrir","nuvem","obcecado","obedecer","objetivo","obrigado","obscuro","obstetra","obter","obturar","ocidente","ocioso","ocorrer","oculista","ocupado","ofegante","ofensiva","oferenda","oficina","ofuscado","ogiva","olaria","oleoso","olhar","oliveira","ombro","omelete","omisso","omitir","ondulado","oneroso","ontem","opcional","operador","oponente","oportuno","oposto","orar","orbitar","ordem","ordinal","orfanato","orgasmo","orgulho","oriental","origem","oriundo","orla","ortodoxo","orvalho","oscilar","ossada","osso","ostentar","otimismo","ousadia","outono","outubro","ouvido","ovelha","ovular","oxidar","oxigenar","pacato","paciente","pacote","pactuar","padaria","padrinho","pagar","pagode","painel","pairar","paisagem","palavra","palestra","palheta","palito","palmada","palpitar","pancada","panela","panfleto","panqueca","pantanal","papagaio","papelada","papiro","parafina","parcial","pardal","parede","partida","pasmo","passado","pastel","patamar","patente","patinar","patrono","paulada","pausar","peculiar","pedalar","pedestre","pediatra","pedra","pegada","peitoral","peixe","pele","pelicano","penca","pendurar","peneira","penhasco","pensador","pente","perceber","perfeito","pergunta","perito","permitir","perna","perplexo","persiana","pertence","peruca","pescado","pesquisa","pessoa","petiscar","piada","picado","piedade","pigmento","pilastra","pilhado","pilotar","pimenta","pincel","pinguim","pinha","pinote","pintar","pioneiro","pipoca","piquete","piranha","pires","pirueta","piscar","pistola","pitanga","pivete","planta","plaqueta","platina","plebeu","plumagem","pluvial","pneu","poda","poeira","poetisa","polegada","policiar","poluente","polvilho","pomar","pomba","ponderar","pontaria","populoso","porta","possuir","postal","pote","poupar","pouso","povoar","praia","prancha","prato","praxe","prece","predador","prefeito","premiar","prensar","preparar","presilha","pretexto","prevenir","prezar","primata","princesa","prisma","privado","processo","produto","profeta","proibido","projeto","prometer","propagar","prosa","protetor","provador","publicar","pudim","pular","pulmonar","pulseira","punhal","punir","pupilo","pureza","puxador","quadra","quantia","quarto","quase","quebrar","queda","queijo","quente","querido","quimono","quina","quiosque","rabanada","rabisco","rachar","racionar","radial","raiar","rainha","raio","raiva","rajada","ralado","ramal","ranger","ranhura","rapadura","rapel","rapidez","raposa","raquete","raridade","rasante","rascunho","rasgar","raspador","rasteira","rasurar","ratazana","ratoeira","realeza","reanimar","reaver","rebaixar","rebelde","rebolar","recado","recente","recheio","recibo","recordar","recrutar","recuar","rede","redimir","redonda","reduzida","reenvio","refinar","refletir","refogar","refresco","refugiar","regalia","regime","regra","reinado","reitor","rejeitar","relativo","remador","remendo","remorso","renovado","reparo","repelir","repleto","repolho","represa","repudiar","requerer","resenha","resfriar","resgatar","residir","resolver","respeito","ressaca","restante","resumir","retalho","reter","retirar","retomada","retratar","revelar","revisor","revolta","riacho","rica","rigidez","rigoroso","rimar","ringue","risada","risco","risonho","robalo","rochedo","rodada","rodeio","rodovia","roedor","roleta","romano","roncar","rosado","roseira","rosto","rota","roteiro","rotina","rotular","rouco","roupa","roxo","rubro","rugido","rugoso","ruivo","rumo","rupestre","russo","sabor","saciar","sacola","sacudir","sadio","safira","saga","sagrada","saibro","salada","saleiro","salgado","saliva","salpicar","salsicha","saltar","salvador","sambar","samurai","sanar","sanfona","sangue","sanidade","sapato","sarda","sargento","sarjeta","saturar","saudade","saxofone","sazonal","secar","secular","seda","sedento","sediado","sedoso","sedutor","segmento","segredo","segundo","seiva","seleto","selvagem","semanal","semente","senador","senhor","sensual","sentado","separado","sereia","seringa","serra","servo","setembro","setor","sigilo","silhueta","silicone","simetria","simpatia","simular","sinal","sincero","singular","sinopse","sintonia","sirene","siri","situado","soberano","sobra","socorro","sogro","soja","solda","soletrar","solteiro","sombrio","sonata","sondar","sonegar","sonhador","sono","soprano","soquete","sorrir","sorteio","sossego","sotaque","soterrar","sovado","sozinho","suavizar","subida","submerso","subsolo","subtrair","sucata","sucesso","suco","sudeste","sufixo","sugador","sugerir","sujeito","sulfato","sumir","suor","superior","suplicar","suposto","suprimir","surdina","surfista","surpresa","surreal","surtir","suspiro","sustento","tabela","tablete","tabuada","tacho","tagarela","talher","talo","talvez","tamanho","tamborim","tampa","tangente","tanto","tapar","tapioca","tardio","tarefa","tarja","tarraxa","tatuagem","taurino","taxativo","taxista","teatral","tecer","tecido","teclado","tedioso","teia","teimar","telefone","telhado","tempero","tenente","tensor","tentar","termal","terno","terreno","tese","tesoura","testado","teto","textura","texugo","tiara","tigela","tijolo","timbrar","timidez","tingido","tinteiro","tiragem","titular","toalha","tocha","tolerar","tolice","tomada","tomilho","tonel","tontura","topete","tora","torcido","torneio","torque","torrada","torto","tostar","touca","toupeira","toxina","trabalho","tracejar","tradutor","trafegar","trajeto","trama","trancar","trapo","traseiro","tratador","travar","treino","tremer","trepidar","trevo","triagem","tribo","triciclo","tridente","trilogia","trindade","triplo","triturar","triunfal","trocar","trombeta","trova","trunfo","truque","tubular","tucano","tudo","tulipa","tupi","turbo","turma","turquesa","tutelar","tutorial","uivar","umbigo","unha","unidade","uniforme","urologia","urso","urtiga","urubu","usado","usina","usufruir","vacina","vadiar","vagaroso","vaidoso","vala","valente","validade","valores","vantagem","vaqueiro","varanda","vareta","varrer","vascular","vasilha","vassoura","vazar","vazio","veado","vedar","vegetar","veicular","veleiro","velhice","veludo","vencedor","vendaval","venerar","ventre","verbal","verdade","vereador","vergonha","vermelho","verniz","versar","vertente","vespa","vestido","vetorial","viaduto","viagem","viajar","viatura","vibrador","videira","vidraria","viela","viga","vigente","vigiar","vigorar","vilarejo","vinco","vinheta","vinil","violeta","virada","virtude","visitar","visto","vitral","viveiro","vizinho","voador","voar","vogal","volante","voleibol","voltagem","volumoso","vontade","vulto","vuvuzela","xadrez","xarope","xeque","xeretar","xerife","xingar","zangado","zarpar","zebu","zelador","zombar","zoologia","zumbido"]');
const require$$9 = /* @__PURE__ */ JSON.parse('["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual","adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor","army","around","arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction","audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake","aware","away","awesome","awful","awkward","axis","baby","bachelor","bacon","badge","bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain","barrel","base","basic","basket","battle","beach","bean","beauty","because","become","beef","before","begin","behave","behind","believe","below","belt","bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike","bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless","blind","blood","blossom","blouse","blue","blur","blush","board","boat","body","boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain","brand","brass","brave","bread","breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb","bulk","bullet","bundle","bunker","burden","burger","burst","bus","business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp","can","canal","cancel","candy","cannon","canoe","canvas","canyon","capable","capital","captain","car","carbon","card","cargo","carpet","carry","cart","case","cash","casino","castle","casual","cat","catalog","catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century","cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase","chat","cheap","check","cheese","chef","cherry","chest","chicken","chief","child","chimney","choice","choose","chronic","chuckle","chunk","churn","cigar","cinnamon","circle","citizen","city","civil","claim","clap","clarify","claw","clay","clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock","clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut","code","coffee","coil","coin","collect","color","column","combine","come","comfort","comic","common","company","concert","conduct","confirm","congress","connect","consider","control","convince","cook","cool","copper","copy","coral","core","corn","correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crouch","crowd","crucial","cruel","cruise","crumble","crunch","crush","cry","crystal","cube","culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal","debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense","define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk","despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance","divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf","dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo","ecology","economy","edge","edit","educate","effort","egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact","end","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough","enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip","era","erase","erode","erosion","error","erupt","escape","essay","essence","estate","eternal","ethics","evidence","evil","evoke","evolve","exact","example","excess","exchange","excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist","exit","exotic","expand","expect","expire","explain","expose","express","extend","extra","eye","eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame","family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father","fatigue","fault","favorite","feature","february","federal","fee","feed","feel","female","fence","festival","fetch","fever","few","fiber","fiction","field","figure","file","film","filter","final","find","fine","finger","finish","fire","firm","first","fiscal","fish","fit","fitness","fix","flag","flame","flash","flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid","flush","fly","foam","focus","fog","foil","fold","follow","food","foot","force","forest","forget","fork","fortune","forum","forward","fossil","foster","found","fox","fragile","frame","frequent","fresh","friend","fringe","frog","front","frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic","garment","gas","gasp","gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue","goat","goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown","grab","grace","grain","grant","grape","grass","gravity","great","green","grid","grief","grit","grocery","group","grow","grunt","guard","guess","guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy","harbor","hard","harsh","harvest","hat","have","hawk","hazard","head","health","heart","heavy","hedgehog","height","hello","helmet","help","hen","hero","hidden","high","hill","hint","hip","hire","history","hobby","hockey","hold","hole","holiday","hollow","home","honey","hood","hope","horn","horror","horse","hospital","host","hotel","hour","hover","hub","huge","human","humble","humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","idea","identify","idle","ignore","ill","illegal","illness","image","imitate","immense","immune","impact","impose","improve","impulse","inch","include","income","increase","index","indicate","indoor","industry","infant","inflict","inform","inhale","inherit","initial","inject","injury","inmate","inner","innocent","input","inquiry","insane","insect","inside","inspire","install","intact","interest","into","invest","invite","involve","iron","island","isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel","job","join","joke","journey","joy","judge","juice","jump","jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee","knife","knock","know","lab","label","labor","ladder","lady","lake","lamp","language","laptop","large","later","latin","laugh","laundry","lava","law","lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left","leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level","liar","liberty","library","license","life","lift","light","like","limb","limit","link","lion","liquid","list","little","live","lizard","load","loan","lobster","local","lock","logic","lonely","long","loop","lottery","loud","lounge","love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine","mad","magic","magnet","maid","mail","main","major","make","mammal","man","manage","mandate","mango","mansion","manual","maple","marble","march","margin","marine","market","marriage","mask","mass","master","match","material","math","matrix","matter","maximum","maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt","member","memory","mention","menu","mercy","merge","merit","merry","mesh","message","metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor","minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile","model","modify","mom","moment","monitor","monkey","monster","month","moon","moral","more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie","much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual","myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature","near","neck","need","negative","neglect","neither","nephew","nerve","nest","net","network","neutral","never","news","next","nice","night","noble","noise","nominee","noodle","normal","north","nose","notable","note","nothing","notice","novel","now","nuclear","number","nurse","nut","oak","obey","object","oblige","obscure","observe","obtain","obvious","occur","ocean","october","odor","off","offer","office","often","oil","okay","old","olive","olympic","omit","once","one","onion","online","only","open","opera","opinion","oppose","option","orange","orbit","orchard","order","ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output","outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact","paddle","page","pair","palace","palm","panda","panel","panic","panther","paper","parade","parent","park","parrot","party","pass","patch","path","patient","patrol","pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen","penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot","pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate","play","please","pledge","pluck","plug","plunge","poem","poet","point","polar","pole","police","pond","pony","pool","popular","portion","position","possible","post","potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority","prison","private","prize","problem","process","produce","profit","program","project","promote","proof","property","prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin","punch","pupil","puppy","purchase","purity","purpose","purse","push","put","puzzle","pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio","rail","rain","raise","rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven","raw","razor","ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle","reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release","relief","rely","remain","remember","remind","remove","render","renew","rent","reopen","repair","repeat","replace","report","require","rescue","resemble","resist","resource","response","result","retire","retreat","return","reunion","reveal","review","reward","rhythm","rib","ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot","ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket","romance","roof","rookie","room","rose","rotate","rough","round","route","royal","rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness","safe","sail","salad","salmon","salon","salt","salute","same","sample","sand","satisfy","satoshi","sauce","sausage","save","say","scale","scan","scare","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script","scrub","sea","search","season","seat","second","secret","section","security","seed","seek","segment","select","sell","seminar","senior","sense","sentence","series","service","session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop","short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side","siege","sight","sign","silent","silk","silly","silver","similar","simple","since","sing","siren","sister","situate","six","size","skate","sketch","ski","skill","skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight","slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda","soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry","sort","soul","sound","soup","source","south","space","spare","spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider","spike","spin","spirit","split","spoil","sponsor","spoon","sport","spot","spray","spread","spring","spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp","stand","start","state","stay","steak","steel","stem","step","stereo","stick","still","sting","stock","stomach","stone","stool","story","stove","strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny","sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey","suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swift","swim","swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag","tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term","test","text","thank","that","theme","then","theory","there","they","thing","this","thought","three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber","time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler","toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool","tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist","toward","tower","town","toy","track","trade","traffic","tragic","train","transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick","trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust","truth","try","tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle","twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella","unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform","unique","unit","universe","unknown","unlock","until","unusual","unveil","update","upgrade","uphold","upon","upper","upset","urban","urge","usage","use","used","useful","useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","verify","version","very","vessel","veteran","viable","vibrant","vicious","victory","video","view","village","vintage","violin","virtual","virus","visa","visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash","wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather","web","wedding","weekend","weird","welcome","west","wet","whale","what","wheat","wheel","when","where","whip","whisper","wide","width","wife","wild","will","win","window","wine","wing","wink","winner","winter","wire","wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word","work","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year","yellow","you","young","youth","zebra","zero","zone","zoo"]');
var hasRequired_wordlists;
function require_wordlists() {
  if (hasRequired_wordlists) return _wordlists;
  hasRequired_wordlists = 1;
  Object.defineProperty(_wordlists, "__esModule", { value: true });
  const wordlists = {};
  _wordlists.wordlists = wordlists;
  let _default;
  _wordlists._default = _default;
  try {
    _wordlists._default = _default = require$$0;
    wordlists.czech = _default;
  } catch (err) {
  }
  try {
    _wordlists._default = _default = require$$1;
    wordlists.chinese_simplified = _default;
  } catch (err) {
  }
  try {
    _wordlists._default = _default = require$$2;
    wordlists.chinese_traditional = _default;
  } catch (err) {
  }
  try {
    _wordlists._default = _default = require$$3;
    wordlists.korean = _default;
  } catch (err) {
  }
  try {
    _wordlists._default = _default = require$$4;
    wordlists.french = _default;
  } catch (err) {
  }
  try {
    _wordlists._default = _default = require$$5;
    wordlists.italian = _default;
  } catch (err) {
  }
  try {
    _wordlists._default = _default = require$$6;
    wordlists.spanish = _default;
  } catch (err) {
  }
  try {
    _wordlists._default = _default = require$$7;
    wordlists.japanese = _default;
    wordlists.JA = _default;
  } catch (err) {
  }
  try {
    _wordlists._default = _default = require$$8;
    wordlists.portuguese = _default;
  } catch (err) {
  }
  try {
    _wordlists._default = _default = require$$9;
    wordlists.english = _default;
    wordlists.EN = _default;
  } catch (err) {
  }
  return _wordlists;
}
var hasRequiredSrc;
function requireSrc() {
  if (hasRequiredSrc) return src;
  hasRequiredSrc = 1;
  Object.defineProperty(src, "__esModule", { value: true });
  const sha256_1 = require$$0$1;
  const sha512_1 = require$$1$1;
  const pbkdf2_1 = require$$2$1;
  const utils_1 = require$$3$1;
  const _wordlists_1 = require_wordlists();
  let DEFAULT_WORDLIST = _wordlists_1._default;
  const INVALID_MNEMONIC = "Invalid mnemonic";
  const INVALID_ENTROPY = "Invalid entropy";
  const INVALID_CHECKSUM = "Invalid mnemonic checksum";
  const WORDLIST_REQUIRED = "A wordlist is required but a default could not be found.\nPlease pass a 2048 word array explicitly.";
  function normalize(str) {
    return (str || "").normalize("NFKD");
  }
  function lpad(str, padString, length) {
    while (str.length < length) {
      str = padString + str;
    }
    return str;
  }
  function binaryToByte(bin) {
    return parseInt(bin, 2);
  }
  function bytesToBinary(bytes) {
    return bytes.map((x) => lpad(x.toString(2), "0", 8)).join("");
  }
  function deriveChecksumBits(entropyBuffer) {
    const ENT = entropyBuffer.length * 8;
    const CS = ENT / 32;
    const hash = sha256_1.sha256(Uint8Array.from(entropyBuffer));
    return bytesToBinary(Array.from(hash)).slice(0, CS);
  }
  function salt(password) {
    return "mnemonic" + (password || "");
  }
  function mnemonicToSeedSync(mnemonic, password) {
    const mnemonicBuffer = Uint8Array.from(Buffer$1.from(normalize(mnemonic), "utf8"));
    const saltBuffer = Uint8Array.from(Buffer$1.from(salt(normalize(password)), "utf8"));
    const res = pbkdf2_1.pbkdf2(sha512_1.sha512, mnemonicBuffer, saltBuffer, {
      c: 2048,
      dkLen: 64
    });
    return Buffer$1.from(res);
  }
  src.mnemonicToSeedSync = mnemonicToSeedSync;
  function mnemonicToSeed(mnemonic, password) {
    const mnemonicBuffer = Uint8Array.from(Buffer$1.from(normalize(mnemonic), "utf8"));
    const saltBuffer = Uint8Array.from(Buffer$1.from(salt(normalize(password)), "utf8"));
    return pbkdf2_1.pbkdf2Async(sha512_1.sha512, mnemonicBuffer, saltBuffer, {
      c: 2048,
      dkLen: 64
    }).then((res) => Buffer$1.from(res));
  }
  src.mnemonicToSeed = mnemonicToSeed;
  function mnemonicToEntropy(mnemonic, wordlist) {
    wordlist = wordlist || DEFAULT_WORDLIST;
    if (!wordlist) {
      throw new Error(WORDLIST_REQUIRED);
    }
    const words = normalize(mnemonic).split(" ");
    if (words.length % 3 !== 0) {
      throw new Error(INVALID_MNEMONIC);
    }
    const bits = words.map((word) => {
      const index = wordlist.indexOf(word);
      if (index === -1) {
        throw new Error(INVALID_MNEMONIC);
      }
      return lpad(index.toString(2), "0", 11);
    }).join("");
    const dividerIndex = Math.floor(bits.length / 33) * 32;
    const entropyBits = bits.slice(0, dividerIndex);
    const checksumBits = bits.slice(dividerIndex);
    const entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte);
    if (entropyBytes.length < 16) {
      throw new Error(INVALID_ENTROPY);
    }
    if (entropyBytes.length > 32) {
      throw new Error(INVALID_ENTROPY);
    }
    if (entropyBytes.length % 4 !== 0) {
      throw new Error(INVALID_ENTROPY);
    }
    const entropy = Buffer$1.from(entropyBytes);
    const newChecksum = deriveChecksumBits(entropy);
    if (newChecksum !== checksumBits) {
      throw new Error(INVALID_CHECKSUM);
    }
    return entropy.toString("hex");
  }
  src.mnemonicToEntropy = mnemonicToEntropy;
  function entropyToMnemonic(entropy, wordlist) {
    if (!Buffer$1.isBuffer(entropy)) {
      entropy = Buffer$1.from(entropy, "hex");
    }
    wordlist = wordlist || DEFAULT_WORDLIST;
    if (!wordlist) {
      throw new Error(WORDLIST_REQUIRED);
    }
    if (entropy.length < 16) {
      throw new TypeError(INVALID_ENTROPY);
    }
    if (entropy.length > 32) {
      throw new TypeError(INVALID_ENTROPY);
    }
    if (entropy.length % 4 !== 0) {
      throw new TypeError(INVALID_ENTROPY);
    }
    const entropyBits = bytesToBinary(Array.from(entropy));
    const checksumBits = deriveChecksumBits(entropy);
    const bits = entropyBits + checksumBits;
    const chunks = bits.match(/(.{1,11})/g);
    const words = chunks.map((binary) => {
      const index = binaryToByte(binary);
      return wordlist[index];
    });
    return wordlist[0] === "あいこくしん" ? words.join("　") : words.join(" ");
  }
  src.entropyToMnemonic = entropyToMnemonic;
  function generateMnemonic(strength, rng, wordlist) {
    strength = strength || 128;
    if (strength % 32 !== 0) {
      throw new TypeError(INVALID_ENTROPY);
    }
    rng = rng || ((size) => Buffer$1.from(utils_1.randomBytes(size)));
    return entropyToMnemonic(rng(strength / 8), wordlist);
  }
  src.generateMnemonic = generateMnemonic;
  function validateMnemonic(mnemonic, wordlist) {
    try {
      mnemonicToEntropy(mnemonic, wordlist);
    } catch (e) {
      return false;
    }
    return true;
  }
  src.validateMnemonic = validateMnemonic;
  function setDefaultWordlist(language) {
    const result = _wordlists_1.wordlists[language];
    if (result) {
      DEFAULT_WORDLIST = result;
    } else {
      throw new Error('Could not find wordlist for language "' + language + '"');
    }
  }
  src.setDefaultWordlist = setDefaultWordlist;
  function getDefaultWordlist() {
    if (!DEFAULT_WORDLIST) {
      throw new Error("No Default Wordlist set");
    }
    return Object.keys(_wordlists_1.wordlists).filter((lang) => {
      if (lang === "JA" || lang === "EN") {
        return false;
      }
      return _wordlists_1.wordlists[lang].every((word, index) => word === DEFAULT_WORDLIST[index]);
    })[0];
  }
  src.getDefaultWordlist = getDefaultWordlist;
  var _wordlists_2 = require_wordlists();
  src.wordlists = _wordlists_2.wordlists;
  return src;
}
var srcExports = requireSrc();
var browser$1 = { exports: {} };
var ms;
var hasRequiredMs;
function requireMs() {
  if (hasRequiredMs) return ms;
  hasRequiredMs = 1;
  var s = 1e3;
  var m = s * 60;
  var h = m * 60;
  var d = h * 24;
  var w = d * 7;
  var y = d * 365.25;
  ms = function(val, options) {
    options = options || {};
    var type = typeof val;
    if (type === "string" && val.length > 0) {
      return parse2(val);
    } else if (type === "number" && isFinite(val)) {
      return options.long ? fmtLong(val) : fmtShort(val);
    }
    throw new Error(
      "val is not a non-empty string or a valid number. val=" + JSON.stringify(val)
    );
  };
  function parse2(str) {
    str = String(str);
    if (str.length > 100) {
      return;
    }
    var match = /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(
      str
    );
    if (!match) {
      return;
    }
    var n = parseFloat(match[1]);
    var type = (match[2] || "ms").toLowerCase();
    switch (type) {
      case "years":
      case "year":
      case "yrs":
      case "yr":
      case "y":
        return n * y;
      case "weeks":
      case "week":
      case "w":
        return n * w;
      case "days":
      case "day":
      case "d":
        return n * d;
      case "hours":
      case "hour":
      case "hrs":
      case "hr":
      case "h":
        return n * h;
      case "minutes":
      case "minute":
      case "mins":
      case "min":
      case "m":
        return n * m;
      case "seconds":
      case "second":
      case "secs":
      case "sec":
      case "s":
        return n * s;
      case "milliseconds":
      case "millisecond":
      case "msecs":
      case "msec":
      case "ms":
        return n;
      default:
        return void 0;
    }
  }
  function fmtShort(ms2) {
    var msAbs = Math.abs(ms2);
    if (msAbs >= d) {
      return Math.round(ms2 / d) + "d";
    }
    if (msAbs >= h) {
      return Math.round(ms2 / h) + "h";
    }
    if (msAbs >= m) {
      return Math.round(ms2 / m) + "m";
    }
    if (msAbs >= s) {
      return Math.round(ms2 / s) + "s";
    }
    return ms2 + "ms";
  }
  function fmtLong(ms2) {
    var msAbs = Math.abs(ms2);
    if (msAbs >= d) {
      return plural(ms2, msAbs, d, "day");
    }
    if (msAbs >= h) {
      return plural(ms2, msAbs, h, "hour");
    }
    if (msAbs >= m) {
      return plural(ms2, msAbs, m, "minute");
    }
    if (msAbs >= s) {
      return plural(ms2, msAbs, s, "second");
    }
    return ms2 + " ms";
  }
  function plural(ms2, msAbs, n, name) {
    var isPlural = msAbs >= n * 1.5;
    return Math.round(ms2 / n) + " " + name + (isPlural ? "s" : "");
  }
  return ms;
}
var common;
var hasRequiredCommon;
function requireCommon() {
  if (hasRequiredCommon) return common;
  hasRequiredCommon = 1;
  function setup(env) {
    createDebug.debug = createDebug;
    createDebug.default = createDebug;
    createDebug.coerce = coerce;
    createDebug.disable = disable;
    createDebug.enable = enable;
    createDebug.enabled = enabled;
    createDebug.humanize = requireMs();
    createDebug.destroy = destroy;
    Object.keys(env).forEach((key) => {
      createDebug[key] = env[key];
    });
    createDebug.names = [];
    createDebug.skips = [];
    createDebug.formatters = {};
    function selectColor(namespace) {
      let hash = 0;
      for (let i = 0; i < namespace.length; i++) {
        hash = (hash << 5) - hash + namespace.charCodeAt(i);
        hash |= 0;
      }
      return createDebug.colors[Math.abs(hash) % createDebug.colors.length];
    }
    createDebug.selectColor = selectColor;
    function createDebug(namespace) {
      let prevTime;
      let enableOverride = null;
      let namespacesCache;
      let enabledCache;
      function debug2(...args) {
        if (!debug2.enabled) {
          return;
        }
        const self2 = debug2;
        const curr = Number(/* @__PURE__ */ new Date());
        const ms2 = curr - (prevTime || curr);
        self2.diff = ms2;
        self2.prev = prevTime;
        self2.curr = curr;
        prevTime = curr;
        args[0] = createDebug.coerce(args[0]);
        if (typeof args[0] !== "string") {
          args.unshift("%O");
        }
        let index = 0;
        args[0] = args[0].replace(/%([a-zA-Z%])/g, (match, format) => {
          if (match === "%%") {
            return "%";
          }
          index++;
          const formatter = createDebug.formatters[format];
          if (typeof formatter === "function") {
            const val = args[index];
            match = formatter.call(self2, val);
            args.splice(index, 1);
            index--;
          }
          return match;
        });
        createDebug.formatArgs.call(self2, args);
        const logFn = self2.log || createDebug.log;
        logFn.apply(self2, args);
      }
      debug2.namespace = namespace;
      debug2.useColors = createDebug.useColors();
      debug2.color = createDebug.selectColor(namespace);
      debug2.extend = extend;
      debug2.destroy = createDebug.destroy;
      Object.defineProperty(debug2, "enabled", {
        enumerable: true,
        configurable: false,
        get: () => {
          if (enableOverride !== null) {
            return enableOverride;
          }
          if (namespacesCache !== createDebug.namespaces) {
            namespacesCache = createDebug.namespaces;
            enabledCache = createDebug.enabled(namespace);
          }
          return enabledCache;
        },
        set: (v) => {
          enableOverride = v;
        }
      });
      if (typeof createDebug.init === "function") {
        createDebug.init(debug2);
      }
      return debug2;
    }
    function extend(namespace, delimiter) {
      const newDebug = createDebug(this.namespace + (typeof delimiter === "undefined" ? ":" : delimiter) + namespace);
      newDebug.log = this.log;
      return newDebug;
    }
    function enable(namespaces) {
      createDebug.save(namespaces);
      createDebug.namespaces = namespaces;
      createDebug.names = [];
      createDebug.skips = [];
      const split2 = (typeof namespaces === "string" ? namespaces : "").trim().replace(/\s+/g, ",").split(",").filter(Boolean);
      for (const ns of split2) {
        if (ns[0] === "-") {
          createDebug.skips.push(ns.slice(1));
        } else {
          createDebug.names.push(ns);
        }
      }
    }
    function matchesTemplate(search, template) {
      let searchIndex = 0;
      let templateIndex = 0;
      let starIndex = -1;
      let matchIndex = 0;
      while (searchIndex < search.length) {
        if (templateIndex < template.length && (template[templateIndex] === search[searchIndex] || template[templateIndex] === "*")) {
          if (template[templateIndex] === "*") {
            starIndex = templateIndex;
            matchIndex = searchIndex;
            templateIndex++;
          } else {
            searchIndex++;
            templateIndex++;
          }
        } else if (starIndex !== -1) {
          templateIndex = starIndex + 1;
          matchIndex++;
          searchIndex = matchIndex;
        } else {
          return false;
        }
      }
      while (templateIndex < template.length && template[templateIndex] === "*") {
        templateIndex++;
      }
      return templateIndex === template.length;
    }
    function disable() {
      const namespaces = [
        ...createDebug.names,
        ...createDebug.skips.map((namespace) => "-" + namespace)
      ].join(",");
      createDebug.enable("");
      return namespaces;
    }
    function enabled(name) {
      for (const skip of createDebug.skips) {
        if (matchesTemplate(name, skip)) {
          return false;
        }
      }
      for (const ns of createDebug.names) {
        if (matchesTemplate(name, ns)) {
          return true;
        }
      }
      return false;
    }
    function coerce(val) {
      if (val instanceof Error) {
        return val.stack || val.message;
      }
      return val;
    }
    function destroy() {
      console.warn("Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`.");
    }
    createDebug.enable(createDebug.load());
    return createDebug;
  }
  common = setup;
  return common;
}
var hasRequiredBrowser$1;
function requireBrowser$1() {
  if (hasRequiredBrowser$1) return browser$1.exports;
  hasRequiredBrowser$1 = 1;
  (function(module2, exports2) {
    var define_process_env_default = {};
    exports2.formatArgs = formatArgs;
    exports2.save = save;
    exports2.load = load;
    exports2.useColors = useColors;
    exports2.storage = localstorage();
    exports2.destroy = /* @__PURE__ */ (() => {
      let warned = false;
      return () => {
        if (!warned) {
          warned = true;
          console.warn("Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`.");
        }
      };
    })();
    exports2.colors = [
      "#0000CC",
      "#0000FF",
      "#0033CC",
      "#0033FF",
      "#0066CC",
      "#0066FF",
      "#0099CC",
      "#0099FF",
      "#00CC00",
      "#00CC33",
      "#00CC66",
      "#00CC99",
      "#00CCCC",
      "#00CCFF",
      "#3300CC",
      "#3300FF",
      "#3333CC",
      "#3333FF",
      "#3366CC",
      "#3366FF",
      "#3399CC",
      "#3399FF",
      "#33CC00",
      "#33CC33",
      "#33CC66",
      "#33CC99",
      "#33CCCC",
      "#33CCFF",
      "#6600CC",
      "#6600FF",
      "#6633CC",
      "#6633FF",
      "#66CC00",
      "#66CC33",
      "#9900CC",
      "#9900FF",
      "#9933CC",
      "#9933FF",
      "#99CC00",
      "#99CC33",
      "#CC0000",
      "#CC0033",
      "#CC0066",
      "#CC0099",
      "#CC00CC",
      "#CC00FF",
      "#CC3300",
      "#CC3333",
      "#CC3366",
      "#CC3399",
      "#CC33CC",
      "#CC33FF",
      "#CC6600",
      "#CC6633",
      "#CC9900",
      "#CC9933",
      "#CCCC00",
      "#CCCC33",
      "#FF0000",
      "#FF0033",
      "#FF0066",
      "#FF0099",
      "#FF00CC",
      "#FF00FF",
      "#FF3300",
      "#FF3333",
      "#FF3366",
      "#FF3399",
      "#FF33CC",
      "#FF33FF",
      "#FF6600",
      "#FF6633",
      "#FF9900",
      "#FF9933",
      "#FFCC00",
      "#FFCC33"
    ];
    function useColors() {
      if (typeof window !== "undefined" && window.process && (window.process.type === "renderer" || window.process.__nwjs)) {
        return true;
      }
      if (typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/(edge|trident)\/(\d+)/)) {
        return false;
      }
      let m;
      return typeof document !== "undefined" && document.documentElement && document.documentElement.style && document.documentElement.style.WebkitAppearance || // Is firebug? http://stackoverflow.com/a/398120/376773
      typeof window !== "undefined" && window.console && (window.console.firebug || window.console.exception && window.console.table) || // Is firefox >= v31?
      // https://developer.mozilla.org/en-US/docs/Tools/Web_Console#Styling_messages
      typeof navigator !== "undefined" && navigator.userAgent && (m = navigator.userAgent.toLowerCase().match(/firefox\/(\d+)/)) && parseInt(m[1], 10) >= 31 || // Double check webkit in userAgent just in case we are in a worker
      typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/applewebkit\/(\d+)/);
    }
    function formatArgs(args) {
      args[0] = (this.useColors ? "%c" : "") + this.namespace + (this.useColors ? " %c" : " ") + args[0] + (this.useColors ? "%c " : " ") + "+" + module2.exports.humanize(this.diff);
      if (!this.useColors) {
        return;
      }
      const c = "color: " + this.color;
      args.splice(1, 0, c, "color: inherit");
      let index = 0;
      let lastC = 0;
      args[0].replace(/%[a-zA-Z%]/g, (match) => {
        if (match === "%%") {
          return;
        }
        index++;
        if (match === "%c") {
          lastC = index;
        }
      });
      args.splice(lastC, 0, c);
    }
    exports2.log = console.debug || console.log || (() => {
    });
    function save(namespaces) {
      try {
        if (namespaces) {
          exports2.storage.setItem("debug", namespaces);
        } else {
          exports2.storage.removeItem("debug");
        }
      } catch (error) {
      }
    }
    function load() {
      let r;
      try {
        r = exports2.storage.getItem("debug") || exports2.storage.getItem("DEBUG");
      } catch (error) {
      }
      if (!r && typeof process$1 !== "undefined" && "env" in process$1) {
        r = define_process_env_default.DEBUG;
      }
      return r;
    }
    function localstorage() {
      try {
        return localStorage;
      } catch (error) {
      }
    }
    module2.exports = requireCommon()(exports2);
    const { formatters } = module2.exports;
    formatters.j = function(v) {
      try {
        return JSON.stringify(v);
      } catch (error) {
        return "[UnexpectedJSONParseError]: " + error.message;
      }
    };
  })(browser$1, browser$1.exports);
  return browser$1.exports;
}
var browserExports$1 = requireBrowser$1();
var eventsExports = requireEvents();
var empty = null;
var browser;
var hasRequiredBrowser;
function requireBrowser() {
  if (hasRequiredBrowser) return browser;
  hasRequiredBrowser = 1;
  var ws2 = null;
  if (typeof WebSocket !== "undefined") {
    ws2 = WebSocket;
  } else if (typeof MozWebSocket !== "undefined") {
    ws2 = MozWebSocket;
  } else if (typeof globalThis !== "undefined") {
    ws2 = globalThis.WebSocket || globalThis.MozWebSocket;
  } else if (typeof window !== "undefined") {
    ws2 = window.WebSocket || window.MozWebSocket;
  } else if (typeof self !== "undefined") {
    ws2 = self.WebSocket || self.MozWebSocket;
  }
  browser = ws2;
  return browser;
}
var browserExports = requireBrowser();
const WebSocket$1 = /* @__PURE__ */ getDefaultExportFromCjs(browserExports);
function isInteger(value) {
  return INTEGER_REGEX.test(value);
}
var INTEGER_REGEX = /^-?[0-9]+$/;
function isNumber(value) {
  return NUMBER_REGEX.test(value);
}
var NUMBER_REGEX = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;
function isSafeNumber(value, config) {
  var num = parseFloat(value);
  var str = String(num);
  var v = extractSignificantDigits(value);
  var s = extractSignificantDigits(str);
  if (v === s) {
    return true;
  }
  if ((config === null || config === void 0 ? void 0 : config.approx) === true) {
    var requiredDigits = 14;
    if (!isInteger(value) && s.length >= requiredDigits && v.startsWith(s.substring(0, requiredDigits))) {
      return true;
    }
  }
  return false;
}
var UnsafeNumberReason = /* @__PURE__ */ (function(UnsafeNumberReason2) {
  UnsafeNumberReason2["underflow"] = "underflow";
  UnsafeNumberReason2["overflow"] = "overflow";
  UnsafeNumberReason2["truncate_integer"] = "truncate_integer";
  UnsafeNumberReason2["truncate_float"] = "truncate_float";
  return UnsafeNumberReason2;
})({});
function getUnsafeNumberReason(value) {
  if (isSafeNumber(value, {
    approx: false
  })) {
    return void 0;
  }
  if (isInteger(value)) {
    return UnsafeNumberReason.truncate_integer;
  }
  var num = parseFloat(value);
  if (!isFinite(num)) {
    return UnsafeNumberReason.overflow;
  }
  if (num === 0) {
    return UnsafeNumberReason.underflow;
  }
  return UnsafeNumberReason.truncate_float;
}
function extractSignificantDigits(value) {
  return value.replace(EXPONENTIAL_PART_REGEX, "").replace(DOT_REGEX, "").replace(TRAILING_ZEROS_REGEX, "").replace(LEADING_MINUS_AND_ZEROS_REGEX, "");
}
var EXPONENTIAL_PART_REGEX = /[eE][+-]?\d+$/;
var LEADING_MINUS_AND_ZEROS_REGEX = /^-?(0*)?/;
var DOT_REGEX = /\./;
var TRAILING_ZEROS_REGEX = /0+$/;
function _typeof$2(obj) {
  "@babel/helpers - typeof";
  return _typeof$2 = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(obj2) {
    return typeof obj2;
  } : function(obj2) {
    return obj2 && "function" == typeof Symbol && obj2.constructor === Symbol && obj2 !== Symbol.prototype ? "symbol" : typeof obj2;
  }, _typeof$2(obj);
}
function _classCallCheck(instance, Constructor) {
  if (!(instance instanceof Constructor)) {
    throw new TypeError("Cannot call a class as a function");
  }
}
function _defineProperties(target, props) {
  for (var i = 0; i < props.length; i++) {
    var descriptor = props[i];
    descriptor.enumerable = descriptor.enumerable || false;
    descriptor.configurable = true;
    if ("value" in descriptor) descriptor.writable = true;
    Object.defineProperty(target, _toPropertyKey(descriptor.key), descriptor);
  }
}
function _createClass(Constructor, protoProps, staticProps) {
  if (protoProps) _defineProperties(Constructor.prototype, protoProps);
  Object.defineProperty(Constructor, "prototype", { writable: false });
  return Constructor;
}
function _defineProperty(obj, key, value) {
  key = _toPropertyKey(key);
  if (key in obj) {
    Object.defineProperty(obj, key, { value, enumerable: true, configurable: true, writable: true });
  } else {
    obj[key] = value;
  }
  return obj;
}
function _toPropertyKey(arg) {
  var key = _toPrimitive(arg, "string");
  return _typeof$2(key) === "symbol" ? key : String(key);
}
function _toPrimitive(input, hint) {
  if (_typeof$2(input) !== "object" || input === null) return input;
  var prim = input[Symbol.toPrimitive];
  if (prim !== void 0) {
    var res = prim.call(input, hint);
    if (_typeof$2(res) !== "object") return res;
    throw new TypeError("@@toPrimitive must return a primitive value.");
  }
  return (hint === "string" ? String : Number)(input);
}
var LosslessNumber = /* @__PURE__ */ (function() {
  function LosslessNumber2(value) {
    _classCallCheck(this, LosslessNumber2);
    _defineProperty(this, "isLosslessNumber", true);
    if (!isNumber(value)) {
      throw new Error('Invalid number (value: "' + value + '")');
    }
    this.value = value;
  }
  _createClass(LosslessNumber2, [{
    key: "valueOf",
    value: function valueOf() {
      var unsafeReason = getUnsafeNumberReason(this.value);
      if (unsafeReason === void 0 || unsafeReason === UnsafeNumberReason.truncate_float) {
        return parseFloat(this.value);
      }
      if (isInteger(this.value)) {
        return BigInt(this.value);
      }
      throw new Error("Cannot safely convert to number: " + "the value '".concat(this.value, "' would ").concat(unsafeReason, " and become ").concat(parseFloat(this.value)));
    }
    /**
     * Get the value of the LosslessNumber as string.
     */
  }, {
    key: "toString",
    value: function toString2() {
      return this.value;
    }
    // Note: we do NOT implement a .toJSON() method, and you should not implement
    // or use that, it cannot safely turn the numeric value in the string into
    // stringified JSON since it has to be parsed into a number first.
  }]);
  return LosslessNumber2;
})();
function isLosslessNumber(value) {
  return value && _typeof$2(value) === "object" && value.isLosslessNumber === true || false;
}
function parseLosslessNumber(value) {
  return new LosslessNumber(value);
}
function _typeof$1(obj) {
  "@babel/helpers - typeof";
  return _typeof$1 = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(obj2) {
    return typeof obj2;
  } : function(obj2) {
    return obj2 && "function" == typeof Symbol && obj2.constructor === Symbol && obj2 !== Symbol.prototype ? "symbol" : typeof obj2;
  }, _typeof$1(obj);
}
function revive(json, reviver) {
  return reviveValue({
    "": json
  }, "", json, reviver);
}
function reviveValue(context, key, value, reviver) {
  if (Array.isArray(value)) {
    return reviver.call(context, key, reviveArray(value, reviver));
  } else if (value && _typeof$1(value) === "object" && !isLosslessNumber(value)) {
    return reviver.call(context, key, reviveObject(value, reviver));
  } else {
    return reviver.call(context, key, value);
  }
}
function reviveObject(object, reviver) {
  Object.keys(object).forEach(function(key) {
    var value = reviveValue(object, key, object[key], reviver);
    if (value !== void 0) {
      object[key] = value;
    } else {
      delete object[key];
    }
  });
  return object;
}
function reviveArray(array, reviver) {
  for (var i = 0; i < array.length; i++) {
    array[i] = reviveValue(array, i + "", array[i], reviver);
  }
  return array;
}
function _typeof(obj) {
  "@babel/helpers - typeof";
  return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(obj2) {
    return typeof obj2;
  } : function(obj2) {
    return obj2 && "function" == typeof Symbol && obj2.constructor === Symbol && obj2 !== Symbol.prototype ? "symbol" : typeof obj2;
  }, _typeof(obj);
}
function _toConsumableArray(arr) {
  return _arrayWithoutHoles(arr) || _iterableToArray(arr) || _unsupportedIterableToArray(arr) || _nonIterableSpread();
}
function _nonIterableSpread() {
  throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
}
function _unsupportedIterableToArray(o, minLen) {
  if (!o) return;
  if (typeof o === "string") return _arrayLikeToArray(o, minLen);
  var n = Object.prototype.toString.call(o).slice(8, -1);
  if (n === "Object" && o.constructor) n = o.constructor.name;
  if (n === "Map" || n === "Set") return Array.from(o);
  if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen);
}
function _iterableToArray(iter) {
  if (typeof Symbol !== "undefined" && iter[Symbol.iterator] != null || iter["@@iterator"] != null) return Array.from(iter);
}
function _arrayWithoutHoles(arr) {
  if (Array.isArray(arr)) return _arrayLikeToArray(arr);
}
function _arrayLikeToArray(arr, len) {
  if (len == null || len > arr.length) len = arr.length;
  for (var i = 0, arr2 = new Array(len); i < len; i++) arr2[i] = arr[i];
  return arr2;
}
function parse(text, reviver) {
  var parseNumber = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : parseLosslessNumber;
  var i = 0;
  var value = parseValue();
  expectValue(value);
  expectEndOfInput();
  return reviver ? revive(value, reviver) : value;
  function parseObject() {
    if (text.charCodeAt(i) === codeOpeningBrace) {
      i++;
      skipWhitespace();
      var object = {};
      var initial = true;
      while (i < text.length && text.charCodeAt(i) !== codeClosingBrace) {
        if (!initial) {
          eatComma();
          skipWhitespace();
        } else {
          initial = false;
        }
        var start = i;
        var key = parseString();
        if (key === void 0) {
          throwObjectKeyExpected();
        }
        skipWhitespace();
        eatColon();
        var _value = parseValue();
        if (_value === void 0) {
          throwObjectValueExpected();
        }
        if (Object.prototype.hasOwnProperty.call(object, key) && !isDeepEqual(_value, object[key])) {
          throwDuplicateKey(key, start + 1);
        }
        object[key] = _value;
      }
      if (text.charCodeAt(i) !== codeClosingBrace) {
        throwObjectKeyOrEndExpected();
      }
      i++;
      return object;
    }
  }
  function parseArray() {
    if (text.charCodeAt(i) === codeOpeningBracket) {
      i++;
      skipWhitespace();
      var array = [];
      var initial = true;
      while (i < text.length && text.charCodeAt(i) !== codeClosingBracket) {
        if (!initial) {
          eatComma();
        } else {
          initial = false;
        }
        var _value2 = parseValue();
        expectArrayItem(_value2);
        array.push(_value2);
      }
      if (text.charCodeAt(i) !== codeClosingBracket) {
        throwArrayItemOrEndExpected();
      }
      i++;
      return array;
    }
  }
  function parseValue() {
    var _ref, _ref2, _ref3, _ref4, _ref5, _parseString;
    skipWhitespace();
    var value2 = (_ref = (_ref2 = (_ref3 = (_ref4 = (_ref5 = (_parseString = parseString()) !== null && _parseString !== void 0 ? _parseString : parseNumeric()) !== null && _ref5 !== void 0 ? _ref5 : parseObject()) !== null && _ref4 !== void 0 ? _ref4 : parseArray()) !== null && _ref3 !== void 0 ? _ref3 : parseKeyword("true", true)) !== null && _ref2 !== void 0 ? _ref2 : parseKeyword("false", false)) !== null && _ref !== void 0 ? _ref : parseKeyword("null", null);
    skipWhitespace();
    return value2;
  }
  function parseKeyword(name, value2) {
    if (text.slice(i, i + name.length) === name) {
      i += name.length;
      return value2;
    }
  }
  function skipWhitespace() {
    while (isWhitespace(text.charCodeAt(i))) {
      i++;
    }
  }
  function parseString() {
    if (text.charCodeAt(i) === codeDoubleQuote) {
      i++;
      var result = "";
      while (i < text.length && text.charCodeAt(i) !== codeDoubleQuote) {
        if (text.charCodeAt(i) === codeBackslash) {
          var char = text[i + 1];
          var escapeChar = escapeCharacters[char];
          if (escapeChar !== void 0) {
            result += escapeChar;
            i++;
          } else if (char === "u") {
            if (isHex(text.charCodeAt(i + 2)) && isHex(text.charCodeAt(i + 3)) && isHex(text.charCodeAt(i + 4)) && isHex(text.charCodeAt(i + 5))) {
              result += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16));
              i += 5;
            } else {
              throwInvalidUnicodeCharacter(i);
            }
          } else {
            throwInvalidEscapeCharacter(i);
          }
        } else {
          if (isValidStringCharacter(text.charCodeAt(i))) {
            result += text[i];
          } else {
            throwInvalidCharacter(text[i]);
          }
        }
        i++;
      }
      expectEndOfString();
      i++;
      return result;
    }
  }
  function parseNumeric() {
    var start = i;
    if (text.charCodeAt(i) === codeMinus) {
      i++;
      expectDigit(start);
    }
    if (text.charCodeAt(i) === codeZero) {
      i++;
    } else if (isNonZeroDigit(text.charCodeAt(i))) {
      i++;
      while (isDigit(text.charCodeAt(i))) {
        i++;
      }
    }
    if (text.charCodeAt(i) === codeDot) {
      i++;
      expectDigit(start);
      while (isDigit(text.charCodeAt(i))) {
        i++;
      }
    }
    if (text.charCodeAt(i) === codeLowercaseE || text.charCodeAt(i) === codeUppercaseE) {
      i++;
      if (text.charCodeAt(i) === codeMinus || text.charCodeAt(i) === codePlus) {
        i++;
      }
      expectDigit(start);
      while (isDigit(text.charCodeAt(i))) {
        i++;
      }
    }
    if (i > start) {
      return parseNumber(text.slice(start, i));
    }
  }
  function eatComma() {
    if (text.charCodeAt(i) !== codeComma) {
      throw new SyntaxError("Comma ',' expected after value ".concat(gotAt()));
    }
    i++;
  }
  function eatColon() {
    if (text.charCodeAt(i) !== codeColon) {
      throw new SyntaxError("Colon ':' expected after property name ".concat(gotAt()));
    }
    i++;
  }
  function expectValue(value2) {
    if (value2 === void 0) {
      throw new SyntaxError("JSON value expected ".concat(gotAt()));
    }
  }
  function expectArrayItem(value2) {
    if (value2 === void 0) {
      throw new SyntaxError("Array item expected ".concat(gotAt()));
    }
  }
  function expectEndOfInput() {
    if (i < text.length) {
      throw new SyntaxError("Expected end of input ".concat(gotAt()));
    }
  }
  function expectDigit(start) {
    if (!isDigit(text.charCodeAt(i))) {
      var numSoFar = text.slice(start, i);
      throw new SyntaxError("Invalid number '".concat(numSoFar, "', expecting a digit ").concat(gotAt()));
    }
  }
  function expectEndOfString() {
    if (text.charCodeAt(i) !== codeDoubleQuote) {
      throw new SyntaxError(`End of string '"' expected `.concat(gotAt()));
    }
  }
  function throwObjectKeyExpected() {
    throw new SyntaxError("Quoted object key expected ".concat(gotAt()));
  }
  function throwDuplicateKey(key, pos2) {
    throw new SyntaxError("Duplicate key '".concat(key, "' encountered at position ").concat(pos2));
  }
  function throwObjectKeyOrEndExpected() {
    throw new SyntaxError("Quoted object key or end of object '}' expected ".concat(gotAt()));
  }
  function throwArrayItemOrEndExpected() {
    throw new SyntaxError("Array item or end of array ']' expected ".concat(gotAt()));
  }
  function throwInvalidCharacter(char) {
    throw new SyntaxError("Invalid character '".concat(char, "' ").concat(pos()));
  }
  function throwInvalidEscapeCharacter(start) {
    var chars = text.slice(start, start + 2);
    throw new SyntaxError("Invalid escape character '".concat(chars, "' ").concat(pos()));
  }
  function throwObjectValueExpected() {
    throw new SyntaxError("Object value expected after ':' ".concat(pos()));
  }
  function throwInvalidUnicodeCharacter(start) {
    var end = start + 2;
    while (/\w/.test(text[end])) {
      end++;
    }
    var chars = text.slice(start, end);
    throw new SyntaxError("Invalid unicode character '".concat(chars, "' ").concat(pos()));
  }
  function pos() {
    return "at position ".concat(i);
  }
  function got() {
    return i < text.length ? "but got '".concat(text[i], "'") : "but reached end of input";
  }
  function gotAt() {
    return got() + " " + pos();
  }
}
function isWhitespace(code) {
  return code === codeSpace || code === codeNewline || code === codeTab || code === codeReturn;
}
function isHex(code) {
  return code >= codeZero && code <= codeNine || code >= codeUppercaseA && code <= codeUppercaseF || code >= codeLowercaseA && code <= codeLowercaseF;
}
function isDigit(code) {
  return code >= codeZero && code <= codeNine;
}
function isNonZeroDigit(code) {
  return code >= codeOne && code <= codeNine;
}
function isValidStringCharacter(code) {
  return code >= 32 && code <= 1114111;
}
function isDeepEqual(a, b) {
  if (a === b) {
    return true;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every(function(item, index) {
      return isDeepEqual(item, b[index]);
    });
  }
  if (isObject(a) && isObject(b)) {
    var keys = _toConsumableArray(new Set([].concat(_toConsumableArray(Object.keys(a)), _toConsumableArray(Object.keys(b)))));
    return keys.every(function(key) {
      return isDeepEqual(a[key], b[key]);
    });
  }
  return false;
}
function isObject(value) {
  return _typeof(value) === "object" && value !== null;
}
var escapeCharacters = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "	"
  // note that \u is handled separately in parseString()
};
var codeBackslash = 92;
var codeOpeningBrace = 123;
var codeClosingBrace = 125;
var codeOpeningBracket = 91;
var codeClosingBracket = 93;
var codeSpace = 32;
var codeNewline = 10;
var codeTab = 9;
var codeReturn = 13;
var codeDoubleQuote = 34;
var codePlus = 43;
var codeMinus = 45;
var codeZero = 48;
var codeOne = 49;
var codeNine = 57;
var codeComma = 44;
var codeDot = 46;
var codeColon = 58;
var codeUppercaseA = 65;
var codeLowercaseA = 97;
var codeUppercaseE = 69;
var codeLowercaseE = 101;
var codeUppercaseF = 70;
var codeLowercaseF = 102;
const debug = {
  client: browserExports$1.debug("electrum-cash:client "),
  cluster: browserExports$1.debug("electrum-cash:cluster"),
  errors: browserExports$1.debug("electrum-cash:error  "),
  warning: browserExports$1.debug("electrum-cash:warning"),
  network: browserExports$1.debug("electrum-cash:network"),
  ping: browserExports$1.debug("electrum-cash:pulses ")
};
debug.client.color = "2";
debug.cluster.color = "3";
debug.errors.color = "9";
debug.warning.color = "13";
debug.network.color = "4";
debug.ping.color = "8";
class ElectrumProtocol {
  /**
   * Helper function that builds an Electrum request object.
   *
   * @param {string} method       method to call.
   * @param {array}  parameters   method parameters for the call.
   * @param {string} requestId    unique string or number referencing this request.
   *
   * @returns a properly formatted Electrum request string.
   */
  static buildRequestObject(method, parameters, requestId) {
    return JSON.stringify({ method, params: parameters, id: requestId });
  }
  /**
   * Constant used to verify if a provided string is a valid version number.
   *
   * @returns a regular expression that matches valid version numbers.
   */
  static get versionRegexp() {
    return /^\d+(\.\d+)+$/;
  }
  /**
   * Constant used to separate statements/messages in a stream of data.
   *
   * @returns the delimiter used by Electrum to separate statements.
   */
  static get statementDelimiter() {
    return "\n";
  }
}
const isVersionRejected = function(object) {
  return "error" in object;
};
var ClusterOrder;
(function(ClusterOrder2) {
  ClusterOrder2[ClusterOrder2["RANDOM"] = 0] = "RANDOM";
  ClusterOrder2[ClusterOrder2["PRIORITY"] = 1] = "PRIORITY";
})(ClusterOrder || (ClusterOrder = {}));
var ClusterDistribution;
(function(ClusterDistribution2) {
  ClusterDistribution2[ClusterDistribution2["ALL"] = 0] = "ALL";
})(ClusterDistribution || (ClusterDistribution = {}));
var ClusterStatus;
(function(ClusterStatus2) {
  ClusterStatus2[ClusterStatus2["DISABLED"] = 0] = "DISABLED";
  ClusterStatus2[ClusterStatus2["DEGRADED"] = 1] = "DEGRADED";
  ClusterStatus2[ClusterStatus2["READY"] = 2] = "READY";
})(ClusterStatus || (ClusterStatus = {}));
var ClientState;
(function(ClientState2) {
  ClientState2[ClientState2["UNAVAILABLE"] = 0] = "UNAVAILABLE";
  ClientState2[ClientState2["AVAILABLE"] = 1] = "AVAILABLE";
})(ClientState || (ClientState = {}));
var ConnectionStatus;
(function(ConnectionStatus2) {
  ConnectionStatus2[ConnectionStatus2["DISCONNECTED"] = 0] = "DISCONNECTED";
  ConnectionStatus2[ConnectionStatus2["CONNECTED"] = 1] = "CONNECTED";
  ConnectionStatus2[ConnectionStatus2["DISCONNECTING"] = 2] = "DISCONNECTING";
  ConnectionStatus2[ConnectionStatus2["CONNECTING"] = 3] = "CONNECTING";
  ConnectionStatus2[ConnectionStatus2["RECONNECTING"] = 4] = "RECONNECTING";
})(ConnectionStatus || (ConnectionStatus = {}));
const ElectrumTransport = {
  TCP: { Scheme: "tcp" },
  TCP_TLS: { Port: 50002, Scheme: "tcp_tls" },
  WS: { Scheme: "ws" },
  WSS: { Scheme: "wss" }
};
const DefaultParameters = {
  // Port number for TCP TLS connections
  PORT: ElectrumTransport.TCP_TLS.Port,
  // Transport to connect to the Electrum server
  TRANSPORT_SCHEME: ElectrumTransport.TCP_TLS.Scheme,
  // How long to wait before attempting to reconnect, in milliseconds.
  RECONNECT: 15 * 1e3,
  // How long to wait for network operations before following up, in milliseconds.
  TIMEOUT: 120 * 1e3,
  // Time between ping messages, in milliseconds. Pinging keeps the connection alive.
  // The reason for pinging this frequently is to detect connection problems early.
  PING_INTERVAL: 3 * 1e3,
  // How many servers we send requests to.
  CLUSTER_DISTRIBUTION: ClusterDistribution.ALL,
  // What order we select servers to send requests to.
  CLUSTER_ORDER: ClusterOrder.RANDOM,
  // If we use lossless json lib to parse json response.
  LOSSLESS_JSON_PARSER: false
};
class ElectrumSocket extends eventsExports.EventEmitter {
  // Declare an empty TCP socket.
  tcpSocket;
  // Declare an empty WebSocket.
  webSocket;
  // Declare timers for keep-alive pings and reconnection
  timers = {};
  // Initialize boolean that indicates whether the onConnect function has run (initialize to false).
  onConnectHasRun = false;
  // Initialize event forwarding functions.
  eventForwarders = {
    disconnect: () => this.emit("disconnect"),
    tcpData: (data) => this.emit("data", data),
    wsData: (event) => this.emit("data", `${event.data}
`),
    tcpError: (err) => this.emit("error", err),
    wsError: (event) => this.emit("error", event.error)
  };
  /**
   * Connect to host:port using the specified transport
   *
   * @param {string} host              Fully qualified domain name or IP address of the host
   * @param {number} port              Network port for the host to connect to
   * @param {TransportScheme} scheme   Transport scheme to use
   * @param {number} timeout           If no connection is established after `timeout` ms, the connection is terminated
   *
   * @throws {Error} if an incorrect transport scheme is specified
   */
  connect(host, port, scheme, timeout) {
    if (this.tcpSocket || this.webSocket) {
      throw new Error("Cannot initiate a new socket connection when an existing connection exists");
    }
    this.timers.disconnect = setTimeout(() => this.disconnectOnTimeout(host, port, timeout), timeout);
    this.once("connect", this.clearDisconnectTimerOnTimeout);
    const socketTypes = {
      [ElectrumTransport.TCP.Scheme]: "a TCP Socket",
      [ElectrumTransport.TCP_TLS.Scheme]: "an encrypted TCP socket",
      [ElectrumTransport.WS.Scheme]: "a WebSocket",
      [ElectrumTransport.WSS.Scheme]: "an encrypted WebSocket"
    };
    debug.network(`Initiating ${socketTypes[scheme]} connection to '${host}:${port}'.`);
    if (scheme === ElectrumTransport.TCP.Scheme || scheme === ElectrumTransport.TCP_TLS.Scheme) {
      if (scheme === ElectrumTransport.TCP_TLS.Scheme) {
        const connectionOptions = { rejectUnauthorized: false };
        if (!empty.isIP(host)) {
          connectionOptions.serverName = host;
        }
        this.tcpSocket = empty.connect(port, host, connectionOptions);
        this.tcpSocket.once("secureConnect", () => {
          if (!(this.tcpSocket instanceof empty.TLSSocket))
            return;
          const authorizationError = this.tcpSocket.authorizationError;
          if (authorizationError === "DEPTH_ZERO_SELF_SIGNED_CERT") {
            debug.warning(`Connection to ${host}:${port} uses a self-signed certificate`);
          }
        });
        this.tcpSocket.on("secureConnect", this.onConnect.bind(this, socketTypes[scheme], host, port));
      } else {
        this.tcpSocket = empty.connect({ host, port });
        this.tcpSocket.on("connect", this.onConnect.bind(this, socketTypes[scheme], host, port));
      }
      this.tcpSocket.setEncoding("utf8");
      this.tcpSocket.setKeepAlive(true, 0);
      this.tcpSocket.setNoDelay(true);
      this.tcpSocket.on("error", this.eventForwarders.tcpError);
    } else if (scheme === ElectrumTransport.WS.Scheme || scheme === ElectrumTransport.WSS.Scheme) {
      if (scheme === ElectrumTransport.WSS.Scheme) {
        this.webSocket = new WebSocket$1(`wss://${host}:${port}`);
      } else {
        this.webSocket = new WebSocket$1(`ws://${host}:${port}`);
      }
      this.webSocket.addEventListener("open", this.onConnect.bind(this, socketTypes[scheme], host, port));
      this.webSocket.addEventListener("error", this.eventForwarders.wsError);
    } else {
      throw new Error("Incorrect transport specified");
    }
  }
  /**
   * Sets up forwarding of events related to the connection.
   *
   * @param {string} connectionType   Name of the connection/transport type, used for logging.
   * @param {string} host             Fully qualified domain name or IP address of the host
   * @param {number} port             Network port for the host to connect to
   */
  onConnect(connectionType, host, port) {
    if (this.onConnectHasRun)
      return;
    debug.network(`Established ${connectionType} connection with '${host}:${port}'.`);
    if (typeof this.tcpSocket !== "undefined") {
      this.tcpSocket.addListener("close", this.eventForwarders.disconnect);
      this.tcpSocket.addListener("data", this.eventForwarders.tcpData);
    } else if (typeof this.webSocket !== "undefined") {
      this.webSocket.addEventListener("close", this.eventForwarders.disconnect);
      this.webSocket.addEventListener("message", this.eventForwarders.wsData);
    }
    this.onConnectHasRun = true;
    this.emit("connect");
  }
  /**
   * Clears the disconnect timer if it is still active.
   */
  clearDisconnectTimerOnTimeout() {
    if (this.timers.disconnect) {
      clearTimeout(this.timers.disconnect);
    }
  }
  /**
   * Forcibly terminate the connection.
   *
   * @throws {Error} if no connection was found
   */
  disconnect() {
    this.clearDisconnectTimerOnTimeout();
    if (this.tcpSocket) {
      this.tcpSocket.removeListener("close", this.eventForwarders.disconnect);
      this.tcpSocket.removeListener("data", this.eventForwarders.tcpData);
      this.tcpSocket.removeListener("error", this.eventForwarders.tcpError);
      this.tcpSocket.destroy();
      this.tcpSocket = void 0;
    } else if (this.webSocket) {
      try {
        this.webSocket.removeEventListener("close", this.eventForwarders.disconnect);
        this.webSocket.removeEventListener("message", this.eventForwarders.wsData);
        this.webSocket.removeEventListener("error", this.eventForwarders.wsError);
        this.webSocket.close();
      } catch (ignored) {
      } finally {
        this.webSocket = void 0;
      }
    }
    this.onConnectHasRun = false;
    this.emit("disconnect");
  }
  /**
   * Write data to the socket
   *
   * @param {Uint8Array | string} data   Data to be written to the socket
   * @param {function} callback          Callback function to be called when the write has completed
   *
   * @throws {Error} if no connection was found
   * @returns true if the message was fully flushed to the socket, false if part of the message
   * is queued in the user memory
   */
  write(data, callback) {
    if (this.tcpSocket) {
      return this.tcpSocket.write(data, callback);
    }
    if (this.webSocket) {
      this.webSocket.send(data, callback);
      return true;
    }
    throw new Error("Cannot write to socket when there is no active connection");
  }
  /**
   * Force a disconnection if no connection is established after `timeout` milliseconds.
   *
   * @param {string} host      Host of the connection that timed out
   * @param {number} port      Port of the connection that timed out
   * @param {number} timeout   Elapsed milliseconds
   */
  disconnectOnTimeout(host, port, timeout) {
    this.removeListener("connect", this.clearDisconnectTimerOnTimeout);
    const timeoutError = { code: "ETIMEDOUT", message: `Connection to '${host}:${port}' timed out after ${timeout} milliseconds` };
    this.emit("error", timeoutError);
    this.disconnect();
  }
}
class ElectrumConnection extends eventsExports.EventEmitter {
  application;
  version;
  host;
  port;
  scheme;
  timeout;
  pingInterval;
  useLosslessJsonParser;
  // Declare an empty socket.
  socket;
  // Declare empty timestamps
  lastReceivedTimestamp;
  // Declare timers for keep-alive pings and reconnection
  timers = {};
  // Initialize an empty array of connection verification timers.
  // eslint-disable-next-line no-undef
  verifications = [];
  // Initialize the connected flag to false to indicate that there is no connection
  status = ConnectionStatus.DISCONNECTED;
  // Initialize messageBuffer to an empty string
  messageBuffer = "";
  /**
   * Sets up network configuration for an Electrum client connection.
   *
   * @param {string} application            your application name, used to identify to the electrum host.
   * @param {string} version                protocol version to use with the host.
   * @param {string} host                   fully qualified domain name or IP number of the host.
   * @param {number} port                   the network port of the host.
   * @param {TransportScheme} scheme        the transport scheme to use for connection
   * @param {number} timeout                how long network delays we will wait for before taking action, in milliseconds.
   * @param {number} pingInterval           the time between sending pings to the electrum host, in milliseconds.
   * @param {boolean} useLosslessJsonParser whether to use lossless json library to handle bigint in response.
   *
   * @throws {Error} if `version` is not a valid version string.
   */
  constructor(application, version, host, port = DefaultParameters.PORT, scheme = DefaultParameters.TRANSPORT_SCHEME, timeout = DefaultParameters.TIMEOUT, pingInterval = DefaultParameters.PING_INTERVAL, useLosslessJsonParser = DefaultParameters.LOSSLESS_JSON_PARSER) {
    super();
    this.application = application;
    this.version = version;
    this.host = host;
    this.port = port;
    this.scheme = scheme;
    this.timeout = timeout;
    this.pingInterval = pingInterval;
    this.useLosslessJsonParser = useLosslessJsonParser;
    if (!ElectrumProtocol.versionRegexp.test(version)) {
      throw new Error(`Provided version string (${version}) is not a valid protocol version number.`);
    }
    this.createSocket();
  }
  /**
   * Returns a string for the host identifier for usage in debug messages.
   */
  get hostIdentifier() {
    return `${this.host}:${this.port}`;
  }
  /**
   * Create and configures a fresh socket and attaches all relevant listeners.
   */
  createSocket() {
    this.socket = new ElectrumSocket();
    this.socket.on("connect", this.onSocketConnect.bind(this));
    this.socket.on("disconnect", this.onSocketDisconnect.bind(this));
    this.socket.on("data", this.parseMessageChunk.bind(this));
  }
  /**
   * Shuts down and destroys the current socket.
   */
  destroySocket() {
    this.socket.disconnect();
  }
  /**
   * Assembles incoming data into statements and hands them off to the message parser.
   *
   * @param {string} data   data to append to the current message buffer, as a string.
   *
   * @throws {SyntaxError} if the passed statement parts are not valid JSON.
   */
  parseMessageChunk(data) {
    this.lastReceivedTimestamp = Date.now();
    this.verifications.forEach((timer) => clearTimeout(timer));
    this.verifications.length = 0;
    this.messageBuffer += data;
    while (this.messageBuffer.includes(ElectrumProtocol.statementDelimiter)) {
      const statementParts = this.messageBuffer.split(ElectrumProtocol.statementDelimiter);
      while (statementParts.length > 1) {
        const currentStatementList = String(statementParts.shift());
        let statementList;
        if (this.useLosslessJsonParser) {
          statementList = parse(currentStatementList, void 0, (value) => {
            return isInteger(value) && (!isSafeNumber(value) || parseInt(value) > Number.MAX_SAFE_INTEGER) ? BigInt(value) : parseFloat(value);
          });
        } else {
          statementList = JSON.parse(currentStatementList);
        }
        if (!Array.isArray(statementList)) {
          statementList = [statementList];
        }
        while (statementList.length > 0) {
          const currentStatement = statementList.shift();
          if (currentStatement.id === "versionNegotiation") {
            if (currentStatement.error) {
              this.emit("version", { error: currentStatement.error });
            } else {
              this.emit("version", { software: currentStatement.result[0], protocol: currentStatement.result[1] });
            }
            continue;
          }
          if (currentStatement.id === "keepAlive") {
            continue;
          }
          this.emit("statement", currentStatement);
        }
      }
      this.messageBuffer = statementParts.shift() || "";
    }
  }
  /**
   * Sends a keep-alive message to the host.
   *
   * @returns true if the ping message was fully flushed to the socket, false if
   * part of the message is queued in the user memory
   */
  ping() {
    debug.ping(`Sending keep-alive ping to '${this.hostIdentifier}'`);
    const message = ElectrumProtocol.buildRequestObject("server.ping", [], "keepAlive");
    const status = this.send(message);
    return status;
  }
  /**
   * Initiates the network connection negotiates a protocol version. Also emits the 'connect' signal if successful.
   *
   * @throws {Error} if the socket connection fails.
   * @returns a promise resolving when the connection is established
   */
  async connect() {
    if (this.status === ConnectionStatus.CONNECTED) {
      return;
    }
    this.status = ConnectionStatus.CONNECTING;
    const connectionResolver = (resolve, reject) => {
      const rejector = (error) => {
        this.status = ConnectionStatus.DISCONNECTED;
        reject(error);
      };
      this.socket.removeAllListeners("error");
      this.socket.once("error", rejector);
      const versionNegotiator = () => {
        debug.network(`Requesting protocol version ${this.version} with '${this.hostIdentifier}'.`);
        this.socket.removeListener("error", rejector);
        const versionMessage = ElectrumProtocol.buildRequestObject("server.version", [this.application, this.version], "versionNegotiation");
        const versionValidator = (version) => {
          if (isVersionRejected(version)) {
            this.disconnect(true);
            const errorMessage = "unsupported protocol version.";
            debug.errors(`Failed to connect with ${this.hostIdentifier} due to ${errorMessage}`);
            reject(errorMessage);
          } else if (version.protocol !== this.version) {
            this.disconnect(true);
            const errorMessage = `incompatible protocol version negotiated (${version.protocol} !== ${this.version}).`;
            debug.errors(`Failed to connect with ${this.hostIdentifier} due to ${errorMessage}`);
            reject(errorMessage);
          } else {
            debug.network(`Negotiated protocol version ${version.protocol} with '${this.hostIdentifier}', powered by ${version.software}.`);
            this.status = ConnectionStatus.CONNECTED;
            this.emit("connect");
            resolve();
          }
        };
        this.once("version", versionValidator);
        this.send(versionMessage);
      };
      this.socket.once("connect", versionNegotiator);
      this.socket.on("error", this.onSocketError.bind(this));
      this.socket.connect(this.host, this.port, this.scheme, this.timeout);
    };
    await new Promise(connectionResolver);
  }
  /**
   * Restores the network connection.
   */
  async reconnect() {
    await this.clearReconnectTimer();
    debug.network(`Trying to reconnect to '${this.hostIdentifier}'..`);
    this.status = ConnectionStatus.RECONNECTING;
    this.destroySocket();
    this.createSocket();
    try {
      await this.connect();
    } catch (error) {
    }
  }
  /**
   * Removes the current reconnect timer.
   */
  clearReconnectTimer() {
    if (this.timers.reconnect) {
      clearTimeout(this.timers.reconnect);
    }
    this.timers.reconnect = void 0;
  }
  /**
   * Removes the current keep-alive timer.
   */
  clearKeepAliveTimer() {
    if (this.timers.keepAlive) {
      clearTimeout(this.timers.keepAlive);
    }
    this.timers.keepAlive = void 0;
  }
  /**
   * Initializes the keep alive timer loop.
   */
  setupKeepAliveTimer() {
    if (!this.timers.keepAlive) {
      this.timers.keepAlive = setTimeout(this.ping.bind(this), this.pingInterval);
    }
  }
  /**
   * Tears down the current connection and removes all event listeners on disconnect.
   *
   * @param {boolean} force   disconnect even if the connection has not been fully established yet.
   *
   * @returns true if successfully disconnected, or false if there was no connection.
   */
  async disconnect(force = false) {
    if (this.status === ConnectionStatus.DISCONNECTED && !force) {
      return false;
    }
    this.status = ConnectionStatus.DISCONNECTING;
    await this.clearKeepAliveTimer();
    await this.clearReconnectTimer();
    const disconnectResolver = (resolve) => {
      this.once("disconnect", () => resolve(true));
      this.destroySocket();
    };
    return new Promise(disconnectResolver);
  }
  /**
   * Sends an arbitrary message to the server.
   *
   * @param {string} message   json encoded request object to send to the server, as a string.
   *
   * @returns true if the message was fully flushed to the socket, false if part of the message
   * is queued in the user memory
   */
  send(message) {
    this.clearKeepAliveTimer();
    const currentTime = Date.now();
    const verificationTimer = setTimeout(this.verifySend.bind(this, currentTime), this.timeout);
    this.verifications.push(verificationTimer);
    this.setupKeepAliveTimer();
    return this.socket.write(message + ElectrumProtocol.statementDelimiter);
  }
  // --- Event managers. --- //
  /**
   * Marks the connection as timed out and schedules reconnection if we have not
   * received data within the expected time frame.
   */
  verifySend(sentTimestamp) {
    if (Number(this.lastReceivedTimestamp) < sentTimestamp) {
      if (this.status === ConnectionStatus.DISCONNECTED || this.status === ConnectionStatus.DISCONNECTING) {
        debug.errors(`Tried to verify already disconnected connection to '${this.hostIdentifier}'`);
        return;
      }
      this.clearKeepAliveTimer();
      debug.network(`Connection to '${this.hostIdentifier}' timed out.`);
      this.socket.disconnect();
    }
  }
  /**
   * Updates the connection status when a connection is confirmed.
   */
  onSocketConnect() {
    this.clearReconnectTimer();
    this.lastReceivedTimestamp = Date.now();
    this.setupKeepAliveTimer();
    this.socket.removeAllListeners("error");
    this.socket.on("error", this.onSocketError.bind(this));
  }
  /**
   * Updates the connection status when a connection is ended.
   */
  onSocketDisconnect() {
    this.emit("disconnect");
    this.clearKeepAliveTimer();
    if (this.status === ConnectionStatus.DISCONNECTING) {
      this.clearReconnectTimer();
      this.removeAllListeners();
      this.status = ConnectionStatus.DISCONNECTED;
      debug.network(`Disconnected from '${this.hostIdentifier}'.`);
    } else {
      if (this.status === ConnectionStatus.CONNECTED) {
        debug.errors(`Connection with '${this.hostIdentifier}' was closed, trying to reconnect in ${DefaultParameters.RECONNECT / 1e3} seconds.`);
      }
      this.status = ConnectionStatus.DISCONNECTED;
      if (!this.timers.reconnect) {
        this.timers.reconnect = setTimeout(this.reconnect.bind(this), DefaultParameters.RECONNECT);
      }
    }
  }
  /**
   * Notify administrator of any unexpected errors.
   */
  onSocketError(error) {
    if (typeof error === "undefined") {
      return;
    }
    if (error.code === "EAI_AGAIN") {
      debug.errors(`Failed to look up DNS records for '${this.host}'.`);
      return;
    }
    if (error.code === "ETIMEDOUT") {
      debug.errors(error.message);
      return;
    }
    debug.errors(`Unknown network error ('${this.hostIdentifier}'): `, error);
  }
}
const isRPCErrorResponse = function(message) {
  return "id" in message && "error" in message;
};
const isRPCNotification = function(message) {
  return !("id" in message) && "method" in message;
};
class ElectrumClient extends eventsExports.EventEmitter {
  // Declare instance variables
  connection;
  // Initialize an empty list of subscription metadata.
  subscriptionMethods = {};
  subscriptionCallbacks = /* @__PURE__ */ new WeakMap();
  // Start counting the request IDs from 0
  requestId = 0;
  // Initialize an empty dictionary for keeping track of request resolvers
  requestResolvers = {};
  /**
   * Initializes an Electrum client.
   *
   * @param {string} application            your application name, used to identify to the electrum host.
   * @param {string} version                protocol version to use with the host.
   * @param {string} host                   fully qualified domain name or IP number of the host.
   * @param {number} port                   the TCP network port of the host.
   * @param {TransportScheme} scheme        the transport scheme to use for connection
   * @param {number} timeout                how long network delays we will wait for before taking action, in milliseconds.
   * @param {number} pingInterval           the time between sending pings to the electrum host, in milliseconds.
   * @param {boolean} useLosslessJsonParser whether to use lossless json library to handle bigint in response.
   *
   * @throws {Error} if `version` is not a valid version string.
   */
  constructor(application, version, host, port = DefaultParameters.PORT, scheme = DefaultParameters.TRANSPORT_SCHEME, timeout = DefaultParameters.TIMEOUT, pingInterval = DefaultParameters.PING_INTERVAL, useLosslessJsonParser = DefaultParameters.LOSSLESS_JSON_PARSER) {
    super();
    this.connection = new ElectrumConnection(application, version, host, port, scheme, timeout, pingInterval, useLosslessJsonParser);
  }
  /**
   * Connects to the remote server.
   *
   * @throws {Error} if the socket connection fails.
   * @returns a promise resolving when the connection is established.
   */
  async connect() {
    this.connection.on("statement", this.response.bind(this));
    this.connection.on("connect", this.resubscribeOnConnect.bind(this));
    this.connection.on("connect", this.emit.bind(this, "connected"));
    this.connection.on("disconnect", this.onConnectionDisconnect.bind(this));
    this.connection.on("error", this.emit.bind(this, "error"));
    await this.connection.connect();
  }
  /**
   * Disconnects from the remote server and removes all event listeners/subscriptions and open requests.
   *
   * @param {boolean} force                 disconnect even if the connection has not been fully established yet.
   * @param {boolean} retainSubscriptions   retain subscription data so they will be restored on reconnection.
   *
   * @returns true if successfully disconnected, or false if there was no connection.
   */
  async disconnect(force = false, retainSubscriptions = false) {
    if (!retainSubscriptions) {
      this.removeAllListeners();
      this.subscriptionMethods = {};
    }
    for (const index in this.requestResolvers) {
      const requestResolver = this.requestResolvers[index];
      requestResolver(new Error("Manual disconnection"));
      delete this.requestResolvers[index];
    }
    return this.connection.disconnect(force);
  }
  /**
   * Calls a method on the remote server with the supplied parameters.
   *
   * @param {string} method          name of the method to call.
   * @param {...string} parameters   one or more parameters for the method.
   *
   * @throws {Error} if the client is disconnected.
   * @returns a promise that resolves with the result of the method or an Error.
   */
  async request(method, ...parameters) {
    if (this.connection.status !== ConnectionStatus.CONNECTED) {
      throw new Error(`Unable to send request to a disconnected server '${this.connection.host}'.`);
    }
    this.requestId += 1;
    const id = this.requestId;
    const message = ElectrumProtocol.buildRequestObject(method, parameters, id);
    const requestResolver = (resolve) => {
      this.requestResolvers[id] = (error, data) => {
        if (error) {
          resolve(error);
        } else {
          resolve(data);
        }
      };
      this.connection.send(message);
    };
    debug.network(`Sending request '${method}' to '${this.connection.host}'`);
    return new Promise(requestResolver);
  }
  /**
   * Subscribes to the method at the server and attaches the callback function to the event feed.
   *
   * @param {function}  callback     a function that should get notification messages.
   * @param {string}    method       one of the subscribable methods the server supports.
   * @param {...string} parameters   one or more parameters for the method.
   *
   * @throws {Error} if the client is disconnected.
   * @returns a promise resolving to true when the subscription is set up.
   */
  async subscribe(callback, method, ...parameters) {
    const subscriptionResolver = async (resolve) => {
      if (!this.listeners(method).includes(callback)) {
        this.addListener(method, callback);
      }
      if (!this.subscriptionMethods[method]) {
        this.subscriptionMethods[method] = [];
      }
      this.subscriptionMethods[method].push(JSON.stringify(parameters));
      const subscriptionCallbackPayloads = this.subscriptionCallbacks.get(callback) || [];
      subscriptionCallbackPayloads.push({ method, payload: JSON.stringify(parameters) });
      this.subscriptionCallbacks.set(callback, subscriptionCallbackPayloads);
      const requestData = await this.request(method, ...parameters);
      callback(requestData);
      resolve(true);
    };
    return new Promise(subscriptionResolver);
  }
  /**
   * Unsubscribes to the method at the server and removes any callback functions
   * when there are no more subscriptions for the method.
   *
   * @param {function}  callback     a function that has previously been subscribed for this method.
   * @param {string}    method       a previously subscribed to method.
   * @param {...string} parameters   one or more parameters for the method.
   *
   * @throws {Error} if no subscriptions exist for the combination of the passed `callback`, `method` and `parameters.
   * @throws {Error} if the client is disconnected.
   * @returns a promise that resolves to true when the subscription has been cancelled.
   */
  async unsubscribe(callback, method, ...parameters) {
    if (this.connection.status !== ConnectionStatus.CONNECTED) {
      throw new Error(`Unable to send unsubscribe request to a disconnected server '${this.connection.host}'.`);
    }
    const subscriptionResolver = async (resolve) => {
      const subscriptionParameters = JSON.stringify(parameters);
      if (!this.subscriptionMethods[method]) {
        throw new Error(`Cannot unsubscribe from '${method}' since the method has no subscriptions.`);
      }
      if (!this.subscriptionCallbacks.has(callback)) {
        throw new Error(`Cannot unsubscribe with '${callback.name}' since the callback has no subscriptions.`);
      }
      const serverMethodPayloadCount = Object.values(this.subscriptionMethods[method]).filter((payload) => payload === subscriptionParameters).length;
      const callbackMethodPayloadCount = (this.subscriptionCallbacks.get(callback) || []).filter((value) => value.method === method).length;
      const serverMethodPayloadIndex = this.subscriptionMethods[method].indexOf(subscriptionParameters);
      const callbackMethodPayloadIndex = (this.subscriptionCallbacks.get(callback) || []).findIndex((value) => value.method === method && value.payload === subscriptionParameters);
      if (serverMethodPayloadIndex < 0) {
        throw new Error(`Cannot unsubscribe from '${method}' since it has no subscription with the given parameters.`);
      }
      if (callbackMethodPayloadIndex < 0) {
        throw new Error(`Cannot unsubscribe with '${callback.name}' since it has no subscription with the given method and parameters.`);
      }
      if (serverMethodPayloadCount === 1) {
        this.subscriptionMethods[method].splice(serverMethodPayloadIndex, 1);
        if (method.endsWith(".subscribe")) {
          await this.request(method.replace(".subscribe", ".unsubscribe"), ...parameters);
        }
      }
      if (callbackMethodPayloadCount === 1) {
        this.removeListener(method, callback);
      }
      const subscriptionCallbackPayloads = this.subscriptionCallbacks.get(callback) || [];
      this.subscriptionCallbacks.set(callback, subscriptionCallbackPayloads.splice(callbackMethodPayloadIndex, 1));
      debug.client(`Unsubscribed callback '${callback.name}' from '${String(method)}' for the '${subscriptionParameters}' parameters.`);
      resolve(true);
    };
    return new Promise(subscriptionResolver);
  }
  /**
   * Restores existing subscriptions without updating status or triggering manual callbacks.
   *
   * @throws {Error} if subscription data cannot be found for all stored event names.
   * @throws {Error} if the client is disconnected.
   * @returns a promise resolving to true when the subscriptions are restored.
   *
   * @ignore
   */
  async resubscribeOnConnect() {
    debug.client(`Connected to '${this.connection.hostIdentifier}'.`);
    for (const method of this.eventNames()) {
      if (method === "connected" || method === "disconnected" || method === "error") {
        continue;
      }
      if (!this.subscriptionMethods[String(method)]) {
        throw new Error(`Unable to resubscribe to ${String(method)} at ${this.connection.hostIdentifier} due to missing subscription data.`);
      }
      for (const parameterJSON of this.subscriptionMethods[String(method)]) {
        const parameters = JSON.parse(parameterJSON);
        await this.request(String(method), ...parameters);
      }
      debug.client(`Restored ${this.subscriptionMethods[String(method)].length} previous '${String(method)}' subscriptions for '${this.connection.hostIdentifier}'`);
    }
    return true;
  }
  /**
   * Parser messages from the remote server to resolve request promises and emit subscription events.
   *
   * @param {RPCNotification | RPCResponse} message   the response message
   *
   * @throws {Error} if the message ID does not match an existing request.
   * @ignore
   */
  response(message) {
    if (isRPCNotification(message)) {
      debug.client(`Received notification for '${message.method}' from '${this.connection.host}'`);
      this.emit(message.method, message.params);
      return;
    }
    if (message.id === null) {
      throw new Error("Internal error: Received an RPC response with ID null.");
    }
    const requestResolver = this.requestResolvers[message.id];
    if (!requestResolver) {
      throw new Error("Internal error: Callback for response not available.");
    }
    delete this.requestResolvers[message.id];
    if (isRPCErrorResponse(message)) {
      requestResolver(new Error(message.error.message));
    } else {
      requestResolver(void 0, message.result);
    }
  }
  /**
   * Callback function that is called when connection to the Electrum server is lost.
   * Aborts all active requests with an error message indicating that connection was lost.
   *
   * @ignore
   */
  onConnectionDisconnect() {
    this.emit("disconnected");
    for (const resolverId in this.requestResolvers) {
      const requestResolver = this.requestResolvers[resolverId];
      requestResolver(new Error("Connection lost"));
      delete this.requestResolvers[resolverId];
    }
  }
}
var ws = null;
if (typeof WebSocket !== "undefined") {
  ws = WebSocket;
} else if (typeof MozWebSocket !== "undefined") {
  ws = MozWebSocket;
} else if (typeof globalThis !== "undefined") {
  ws = globalThis.WebSocket || globalThis.MozWebSocket;
} else if (typeof window !== "undefined") {
  ws = window.WebSocket || window.MozWebSocket;
} else if (typeof self !== "undefined") {
  ws = self.WebSocket || self.MozWebSocket;
}
class $1dee54fbcb867378$export$2e2bcd8739ae039 {
  static {
    this.encoder = new TextEncoder();
  }
  static {
    this.decoder = new TextDecoder();
  }
  static generateSecret() {
    let array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  static async encrypt(message, secret) {
    let salt = crypto.getRandomValues(new Uint8Array(16));
    let iv = crypto.getRandomValues(new Uint8Array(12));
    let key = await this.deriveKey(secret, salt);
    let encodedMessage = this.encoder.encode(message);
    let ciphertext = await crypto.subtle.encrypt({
      name: "AES-GCM",
      iv
    }, key, encodedMessage);
    let combined = this.concatBuffers([
      salt,
      iv,
      new Uint8Array(ciphertext)
    ]);
    return this.base64Encode(combined);
  }
  static async decrypt(encMessage, secret) {
    let data = this.base64Decode(encMessage);
    let salt = data.slice(0, 16);
    let iv = data.slice(16, 28);
    let ciphertext = data.slice(28);
    let key = await this.deriveKey(secret, salt);
    let decrypted = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv
    }, key, ciphertext);
    return this.decoder.decode(decrypted);
  }
  static async deriveKey(secret, salt) {
    let encodedSecret = this.encoder.encode(secret);
    let baseKey = await crypto.subtle.importKey("raw", encodedSecret, "PBKDF2", false, [
      "deriveKey"
    ]);
    return crypto.subtle.deriveKey({
      name: "PBKDF2",
      salt,
      iterations: 1e5,
      hash: "SHA-256"
    }, baseKey, {
      name: "AES-GCM",
      length: 256
    }, false, [
      "encrypt",
      "decrypt"
    ]);
  }
  static concatBuffers(buffers) {
    let totalLength = buffers.reduce((sum, b) => sum + b.length, 0);
    let result = new Uint8Array(totalLength);
    let offset = 0;
    for (let b of buffers) {
      result.set(b, offset);
      offset += b.length;
    }
    return result;
  }
  static base64Encode(data) {
    return btoa(String.fromCharCode(...data));
  }
  static base64Decode(b64) {
    let binary = atob(b64);
    let len = binary.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
}
var $abb7f0d6cff128a3$export$4baa4fd50b453ebf = /* @__PURE__ */ (function(JsonRpcErrorCode) {
  JsonRpcErrorCode[JsonRpcErrorCode["ParseError"] = -32700] = "ParseError";
  JsonRpcErrorCode[JsonRpcErrorCode["InvalidRequest"] = -32600] = "InvalidRequest";
  JsonRpcErrorCode[JsonRpcErrorCode["MethodNotFound"] = -32601] = "MethodNotFound";
  JsonRpcErrorCode[JsonRpcErrorCode["InvalidParams"] = -32602] = "InvalidParams";
  JsonRpcErrorCode[JsonRpcErrorCode["InternalError"] = -32603] = "InternalError";
  JsonRpcErrorCode[JsonRpcErrorCode["RequestFailed"] = -32e3] = "RequestFailed";
  JsonRpcErrorCode[JsonRpcErrorCode["RequestCancelled"] = -32001] = "RequestCancelled";
  JsonRpcErrorCode[JsonRpcErrorCode["RequestRejected"] = -32003] = "RequestRejected";
  JsonRpcErrorCode[JsonRpcErrorCode["SessionNotFound"] = -32004] = "SessionNotFound";
  JsonRpcErrorCode[JsonRpcErrorCode["RequestTimeout"] = -32008] = "RequestTimeout";
  JsonRpcErrorCode[JsonRpcErrorCode["SessionConflict"] = -32009] = "SessionConflict";
  JsonRpcErrorCode[JsonRpcErrorCode["ConnectionClosed"] = -32010] = "ConnectionClosed";
  JsonRpcErrorCode[JsonRpcErrorCode["InvalidResponse"] = -32052] = "InvalidResponse";
  return JsonRpcErrorCode;
})({});
class $abb7f0d6cff128a3$export$67bbc29c133d62a1 extends Error {
  constructor(code, message) {
    super(message), this.code = code;
    this.name = "JsonRpcError";
  }
}
class $770bd20b531dfe71$export$2e2bcd8739ae039 {
  constructor(url, secret) {
    this.url = url;
    this.secret = secret;
    this.pending = /* @__PURE__ */ new Map();
    this.handlers = /* @__PURE__ */ new Map();
    this.nextId = 1;
    this.pingInterval = 15e3;
  }
  initializeWebSocket() {
    this.ws = new ws(this.url);
    this.ws.onmessage = async (event) => {
      let msg;
      try {
        msg = await (0, $1dee54fbcb867378$export$2e2bcd8739ae039).decrypt(event.data, this.secret);
      } catch {
        msg = event.data;
      }
      this.handleMessage(msg);
    };
    this.ws.onclose = () => {
      this.clearKeepAliveTimer();
      for (let [, { reject }] of this.pending.entries()) reject(new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.ConnectionClosed, "Connection closed."));
      this.pending.clear();
      if (this.onCloseHandler) this.onCloseHandler();
    };
    this.ws.onerror = () => {
      this.ws.close();
    };
  }
  async connect(timeout) {
    this.initializeWebSocket();
    if (this.ws.readyState !== ws.OPEN) await new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.ws.onopen = null;
        this.ws.onerror = null;
        if (this.ws.readyState !== ws.CLOSED) this.ws.close();
        reject(new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.RequestTimeout, `Connection timeout.`));
      }, timeout);
      const originalOnError = this.ws.onerror;
      this.ws.onopen = () => {
        clearTimeout(timeoutId);
        this.ws.onerror = originalOnError;
        resolve();
      };
      this.ws.onerror = () => {
        clearTimeout(timeoutId);
        this.ws.onerror = originalOnError;
        reject(new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.RequestFailed, "Connection failed."));
      };
    });
  }
  disconnect() {
    this.clearKeepAliveTimer();
    if (this.ws && this.ws.readyState === ws.OPEN) this.ws.close();
  }
  onClose(handler) {
    this.onCloseHandler = handler;
  }
  setupKeepAliveTimer() {
    if (this.keepAliveTimer) return;
    this.keepAliveTimer = setTimeout(() => {
      this.send(JSON.stringify({
        jsonrpc: "2.0",
        id: "keepAlive",
        method: "wl_ping"
      }));
    }, this.pingInterval);
  }
  clearKeepAliveTimer() {
    if (this.keepAliveTimer) {
      clearTimeout(this.keepAliveTimer);
      this.keepAliveTimer = void 0;
    }
  }
  send(data) {
    this.clearKeepAliveTimer();
    if (this.ws.readyState !== ws.OPEN) throw new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.ConnectionClosed, "Connection closed.");
    this.setupKeepAliveTimer();
    this.ws.send(data);
  }
  async request(method, params, options) {
    let id = (this.nextId++).toString();
    let payload = {
      jsonrpc: "2.0",
      id,
      method,
      params
    };
    let raw = JSON.stringify(payload);
    let msg = options?.encrypted === false ? raw : await $1dee54fbcb867378$export$2e2bcd8739ae039.encrypt(raw, this.secret);
    this.send(msg);
    return new Promise((resolve, reject) => {
      const cleanUp = () => {
        clearTimeout(timeoutId);
        options.signal?.removeEventListener("abort", onAbort);
        this.pending.delete(id);
      };
      const onAbort = () => {
        cleanUp();
        reject(new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.RequestCancelled, "Request was cancelled."));
      };
      const timeoutId = setTimeout(() => {
        cleanUp();
        reject(new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.RequestTimeout, "Request timeout."));
      }, options.timeout);
      if (options?.signal?.aborted) {
        onAbort();
        return;
      }
      options.signal?.addEventListener("abort", onAbort);
      this.pending.set(id, {
        resolve: (result) => {
          cleanUp();
          resolve(result);
        },
        reject: (err) => {
          cleanUp();
          reject(err);
        }
      });
    });
  }
  async notify(method, params) {
    let payload = {
      jsonrpc: "2.0",
      method,
      params
    };
    let encrypted = await $1dee54fbcb867378$export$2e2bcd8739ae039.encrypt(JSON.stringify(payload), this.secret);
    this.send(encrypted);
  }
  on(method, handler) {
    this.handlers.set(method, handler);
  }
  off(method) {
    this.handlers.delete(method);
  }
  async handleMessage(raw) {
    let msg = JSON.parse(raw);
    if (this.isJsonRpcResponse(msg)) {
      let cb = this.pending.get(msg.id);
      if (cb) {
        this.pending.delete(msg.id);
        if (msg.error) cb.reject(new $abb7f0d6cff128a3$export$67bbc29c133d62a1(msg.error.code, msg.error.message));
        else cb.resolve(msg.result);
      }
    } else if (this.isJsonRpcRequest(msg) || this.isJsonRpcNotification(msg)) {
      let handler = this.handlers.get(msg.method);
      if (handler) {
        let { result, error } = await this.processMessage(msg, handler);
        if (!this.isJsonRpcRequest(msg)) return;
        if (!result && !error) error = {
          code: $abb7f0d6cff128a3$export$4baa4fd50b453ebf.InvalidResponse,
          message: "Handler returned neither result nor error"
        };
        let response = {
          jsonrpc: "2.0",
          id: msg.id,
          result,
          error
        };
        let encrypted = await $1dee54fbcb867378$export$2e2bcd8739ae039.encrypt(JSON.stringify(response), this.secret);
        this.send(encrypted);
      }
    }
  }
  async processMessage(msg, handler) {
    let result, error;
    try {
      if (Array.isArray(msg.params)) result = await handler(...msg.params);
      else if (msg.params && typeof msg.params === "object") result = await handler(msg.params);
      else result = await handler();
      if (this.isJsonRpcErrorData(result)) {
        error = {
          code: result.code,
          message: result.message
        };
        result = void 0;
      }
    } catch (err) {
      if (this.isJsonRpcErrorData(err)) error = {
        code: err.code,
        message: err.message
      };
      else error = {
        code: $abb7f0d6cff128a3$export$4baa4fd50b453ebf.RequestFailed,
        message: `Request failed. ${err instanceof Error ? err.message : ""}`
      };
    }
    return {
      result,
      error
    };
  }
  isJsonRpcResponse(msg) {
    return typeof msg === "object" && msg !== null && "jsonrpc" in msg && msg.jsonrpc === "2.0" && "id" in msg && ("result" in msg || "error" in msg);
  }
  isJsonRpcRequest(msg) {
    return typeof msg === "object" && msg !== null && "jsonrpc" in msg && msg.jsonrpc === "2.0" && "id" in msg && "method" in msg;
  }
  isJsonRpcNotification(msg) {
    return typeof msg === "object" && msg !== null && "jsonrpc" in msg && msg.jsonrpc === "2.0" && "method" in msg && !("id" in msg);
  }
  isJsonRpcErrorData(data) {
    return typeof data === "object" && data !== null && "code" in data && typeof data.code === "number" && "message" in data && typeof data.message === "string";
  }
}
class $69598d18f252c5a5$export$2e2bcd8739ae039 {
  /**
  * Creates an instance of PeerProvider.
  * 
  * @param version - The protocol version.
  * @param relayUrl - The URL of the relay server.
  * @param secret - The shared secret for encryption.
  * @param sessionId - The session ID. Defaults to an empty string.
  */
  constructor(version, relayUrl, secret, sessionId = "") {
    this.version = version;
    this.relayUrl = relayUrl;
    this.secret = secret;
    this.sessionId = sessionId;
    this.client = new $770bd20b531dfe71$export$2e2bcd8739ae039(this.relayUrl, this.secret);
  }
  getSessionInfo() {
    return {
      version: this.version,
      relayUrl: this.relayUrl,
      sessionId: this.sessionId,
      secret: this.secret
    };
  }
  /**
  * Connects to the relay server.
  * 
  * @param timeoutMs - The connection timeout in milliseconds. Default is 10,000ms.
  * @returns A promise that resolves when the connection is established.
  */
  async connect(timeoutMs = 1e4) {
    return this.client.connect(timeoutMs);
  }
  disconnect() {
    this.client.disconnect();
  }
  /**
  * Sends a JSON-RPC request to the peer.
  * 
  * @param method - The RPC method name.
  * @param params - The RPC method parameters.
  * @param options - The request options, including timeout. Default timeout is 30,000ms.
  * @returns A promise that resolves with the result of the RPC method.
  */
  async sendRequest(method, params, options = {
    timeout: 3e4
  }) {
    return this.client.request(method, params, options);
  }
  /**
  * Sends a JSON-RPC notification to the peer.
  * 
  * @param method - The RPC method name.
  * @param params - The RPC method parameters.
  */
  async sendNotification(method, params) {
    await this.client.notify(method, params);
  }
  /**
  * Registers a handler for a specific RPC method.
  * 
  * @param method - The RPC method name.
  * @param handler - The function to handle the RPC request.
  */
  on(method, handler) {
    this.client.on(method, handler);
  }
  /**
  * Removes a handler for a specific RPC method.
  * 
  * @param method - The RPC method name.
  */
  off(method) {
    this.client.off(method);
  }
  /**
  * Registers a handler for when the peer disconnects from the session.
  * 
  * @param handler - The function to handle the peer disconnection.
  */
  onPeerDisconnect(handler) {
    this.on("wl_sessionLeft", handler);
  }
  /**
  * Registers a handler for when the WebSocket connection is closed.
  * 
  * @param handler - The function to handle the connection close event.
  */
  onClose(handler) {
    this.client.onClose(handler);
  }
}
class $fe6ed033804c8bce$export$2e2bcd8739ae039 extends $69598d18f252c5a5$export$2e2bcd8739ae039 {
  /**
  * Creates an instance of DAppProvider.
  * 
  * @param pairingURI - The dApp pairing URI, usually scanned from a QR code.
  */
  constructor(pairingURI) {
    let { version, relayUrl, secret, sessionId } = $fe6ed033804c8bce$export$2e2bcd8739ae039.parsePairingURI(pairingURI);
    super(version, relayUrl, secret, sessionId);
  }
  /**
  * Parses a pairing URI to extract session details.
  * 
  * @param uri - The pairing URI.
  * @returns The session details.
  * @throws If the URI is invalid.
  * @internal
  */
  static parsePairingURI(uri) {
    if (!uri.startsWith("wl:")) throw new Error("Invalid pairing uri prefix");
    const uriBody = uri.substring(3);
    const atIndex = uriBody.indexOf("@");
    if (atIndex < 0) throw new Error("Invalid pairing uri: missing version");
    const version = uriBody.substring(0, atIndex);
    const relayPart = uriBody.substring(atIndex + 1);
    const url = new URL(relayPart);
    const sessionId = url.searchParams.get("session");
    const secret = url.searchParams.get("secret");
    if (!sessionId || !secret) throw new Error("Missing session or secret");
    return {
      version,
      relayUrl: url.origin + url.pathname,
      secret,
      sessionId
    };
  }
  /**
  * Connects to the relay server and retrieves the dApp info from the wallet.
  * 
  * @param timeoutMs - The connection timeout in milliseconds. Default 10_000ms
  * @returns A promise that resolves with the dApp information.
  * @throws If the connection fails or no app info is received.
  */
  async connect(timeoutMs = 1e4) {
    try {
      await super.connect(timeoutMs);
      let appInfo = await this.sendRequest("wl_getAppInfo", [
        this.sessionId
      ], {
        encrypted: false,
        timeout: timeoutMs
      });
      if (!appInfo) throw new Error("No app info received");
      return appInfo;
    } catch (e) {
      super.disconnect();
      throw e;
    }
  }
  /**
  * Notifies the dApp that the wallet has joined the session.
  * 
  * @param walletAddress - The address of the wallet joining the session.
  * @param timeoutMs - The request timeout in milliseconds. Default 10_000ms
  * @returns A promise that resolves to true if the notification was sent successfully.
  * @throws If the operation fails.
  */
  async joinSession(walletAddress, timeoutMs = 1e4) {
    let success = await this.sendRequest("wl_joinSession", [
      this.sessionId
    ], {
      encrypted: false,
      timeout: timeoutMs
    });
    if (!success) throw new Error("Failed to join session");
    await this.sendNotification("wl_sessionJoined", [
      walletAddress
    ]);
    return success;
  }
  /**
  * Registers a handler for the "wallet_signMessage" request from the dApp.
  * 
  * @param handler - The function to handle the sign message request.
  */
  onSignMessage(handler) {
    this.on("wallet_signMessage", handler);
  }
  /**
  * Registers a handler for the "wallet_getAccount" request from the dApp.
  * 
  * @param handler - The function to handle the get account request.
  */
  onGetAccount(handler) {
    this.on("wallet_getAccount", handler);
  }
  /**
  * Registers a handler for the "wallet_addToken" request from the dApp.
  * 
  * @param handler - The function to handle the add token request.
  */
  onAddToken(handler) {
    this.on("wallet_addToken", handler);
  }
  /**
  * Registers a handler for the "wallet_signTransaction" request from the dApp.
  * 
  * @param handler - The function to handle the sign transaction request.
  */
  onSignTransaction(handler) {
    this.on("wallet_signTransaction", handler);
  }
  /**
  * Registers a handler for the "wallet_sendTransaction" request from the dApp.
  * 
  * @param handler - The function to handle the send transaction request.
  */
  onSendTransaction(handler) {
    this.on("wallet_sendTransaction", handler);
  }
  /**
  * Registers a handler for the "wallet_switchNetwork" request from the dApp.
  * 
  * @param handler - The function to handle the switch network request.
  */
  onSwitchNetwork(handler) {
    this.on("wallet_switchNetwork", handler);
  }
}
class $ff9d81fc068ff3b6$export$2e2bcd8739ae039 extends $69598d18f252c5a5$export$2e2bcd8739ae039 {
  /**
  * Creates an instance of WalletProvider.
  * 
  * @param relayUrl - The URL of the relay server.
  * @param appInfo - Information about the dApp.
  * @param version - The protocol version. Default is "1".
  */
  constructor(relayUrl, appInfo, version = "1") {
    super(version, relayUrl, $1dee54fbcb867378$export$2e2bcd8739ae039.generateSecret()), this.appInfo = appInfo;
  }
  /**
  * Connects to the relay server and creates a new session.
  * 
  * @param timeoutMs - The connection timeout in milliseconds. Default is 10,000ms.
  * @returns A promise that resolves when the connection is established and the session is created.
  * @throws If the connection or session creation fails.
  */
  async connect(timeoutMs = 1e4) {
    try {
      await super.connect(timeoutMs);
      let sessionId = await this.sendRequest("wl_createSession", [
        this.appInfo
      ], {
        encrypted: false,
        timeout: timeoutMs
      });
      if (typeof sessionId !== "string") throw new Error("Invalid session ID received from relay");
      this.sessionId = sessionId;
    } catch (e) {
      super.disconnect();
      throw e;
    }
  }
  /**
  * Disconnects from the relay server and cancels any pending wallet connection waits.
  */
  disconnect() {
    this.cancelWaitForWallet();
    super.disconnect();
  }
  /**
  * Gets the pairing URI for the current session.
  * 
  * This URI should be displayed as a QR code for the wallet to scan.
  * 
  * @returns The pairing URI.
  */
  getPairingURI() {
    return `wl:${this.version}@${this.relayUrl}?session=${this.sessionId}&secret=${this.secret}`;
  }
  /**
  * Waits for a wallet to join the session.
  * 
  * @param timeoutMs - The timeout in milliseconds to wait for the wallet. Default is 30,000ms.
  * @returns A promise that resolves with the wallet's address.
  * @throws If the operation times out or is canceled.
  */
  async waitForWallet(timeoutMs = 3e4) {
    if (this.walletWaiterAbortController) throw new Error("Already waiting for wallet");
    this.walletWaiterAbortController = new AbortController();
    let { signal } = this.walletWaiterAbortController;
    return new Promise((resolve, reject) => {
      let timer = setTimeout(() => {
        cleanup();
        reject(new Error("Wallet connection timeout"));
      }, timeoutMs);
      const handler = (address) => {
        cleanup();
        resolve(address);
      };
      const cleanup = () => {
        clearTimeout(timer);
        this.off("wl_sessionJoined");
        this.walletWaiterAbortController = void 0;
      };
      this.on("wl_sessionJoined", handler);
      signal.addEventListener("abort", () => {
        cleanup();
        reject(new Error("Wallet wait canceled"));
      });
    });
  }
  /**
  * Cancels the wait for a wallet to connect.
  */
  cancelWaitForWallet() {
    this.walletWaiterAbortController?.abort();
  }
  /**
  * Requests the connected wallet to sign a message.
  * 
  * @param account - The account address to use for signing.
  * @param message - The message to sign - as utf8 string hex representation.
  * @param timeoutMs - The request timeout in milliseconds. Default is 30,000ms.
  * @param signal - An AbortSignal to cancel the request.
  * @returns A promise that resolves with the signed message.
  * @throws If the wallet is not connected or the request fails.
  */
  async signMessage(account, message, timeoutMs = 3e4, signal) {
    if (!this.sessionId) throw new Error("Not connected to a wallet");
    return this.sendRequest("wallet_signMessage", {
      account,
      message
    }, {
      timeout: timeoutMs,
      signal
    });
  }
  /**
  * Requests the connected wallet's account address.
  * 
  * @param timeoutMs - The request timeout in milliseconds. Default is 30,000ms.
  * @param signal - An AbortSignal to cancel the request.
  * @returns A promise that resolves with the account address.
  * @throws If the wallet is not connected or the request fails.
  */
  async getAccount(timeoutMs = 3e4, signal) {
    if (!this.sessionId) throw new Error("Not connected to a wallet");
    return this.sendRequest("wallet_getAccount", [], {
      timeout: timeoutMs,
      signal
    });
  }
  /**
  * Requests the connected wallet to add a token to its tokens list.
  * 
  * @param account - The account address.
  * @param token - The token identifier to add.
  * @param timeoutMs - The request timeout in milliseconds. Default is 30,000ms.
  * @param signal - An AbortSignal to cancel the request.
  * @returns A promise that resolves to true if the token was added successfully.
  * @throws If the wallet is not connected or the request fails.
  */
  async addToken(account, token, timeoutMs = 3e4, signal) {
    if (!this.sessionId) throw new Error("Not connected to a wallet");
    return this.sendRequest("wallet_addToken", {
      account,
      token
    }, {
      timeout: timeoutMs,
      signal
    });
  }
  /**
  * Requests the connected wallet to sign a transaction.
  *
  * @param account - The account address to use for signing.
  * @param hex - The transaction hex to sign.
  * @param broadcast - Whether to broadcast the transaction after signing.
  * @param timeoutMs - The request timeout in milliseconds. Default is 30,000ms.
  * @param signal - An AbortSignal to cancel the request.
  * @returns A promise that resolves with the signed transaction hex, or transaction ID if broadcast is `true`.
  * @throws If the wallet is not connected or the request fails.
  */
  async signTransaction(account, hex, broadcast, timeoutMs = 3e4, signal) {
    if (!this.sessionId) throw new Error("Not connected to a wallet");
    return this.sendRequest("wallet_signTransaction", {
      account,
      hex,
      broadcast
    }, {
      timeout: timeoutMs,
      signal
    });
  }
  /**
  * Requests the connected wallet to send a transaction.
  *
  * @param from - The sender's address.
  * @param to - The recipient and amount.
  * @param feePerByte - The fee per byte for the transaction.
  * @param data - Optional data to include in the transaction.
  * @param timeoutMs - The request timeout in milliseconds. Default is 30,000ms.
  * @param signal - An AbortSignal to cancel the request.
  * @returns A promise that resolves with the transaction ID.
  * @throws If the wallet is not connected or the request fails.
  */
  async sendTransaction(from, to, feePerByte, data, timeoutMs = 3e4, signal) {
    if (!this.sessionId) throw new Error("Not connected to a wallet");
    return this.sendRequest("wallet_sendTransaction", {
      from,
      to,
      feePerByte,
      data
    }, {
      timeout: timeoutMs,
      signal
    });
  }
  /**
  * Requests the connected wallet to switch to a different network.
  * 
  * @param network - The network to switch to.
  * @param timeoutMs - The request timeout in milliseconds. Default is 30,000ms.
  * @param signal - An AbortSignal to cancel the request.
  * @returns A promise that resolves to true if the network was switched successfully.
  * @throws If the wallet is not connected or the request fails.
  */
  async switchNetwork(network, timeoutMs = 3e4, signal) {
    if (!this.sessionId) throw new Error("Not connected to a wallet");
    return this.sendRequest("wallet_switchNetwork", {
      network
    }, {
      timeout: timeoutMs,
      signal
    });
  }
}
var $parcel$global = globalThis;
var $df64573ef6d51081$exports = {};
$df64573ef6d51081$exports = JSON.parse('{"name":"nexa-wallet-sdk","version":"0.5.3","type":"module","source":"src/index.ts","types":"dist/index.d.ts","main":"dist/index.cjs","module":"dist/index.mjs","browser":"dist/index.web.mjs","exports":{"types":"./dist/index.d.ts","node":{"import":"./dist/index.mjs","require":"./dist/index.cjs"},"browser":"./dist/index.web.mjs","default":"./dist/index.mjs"},"scripts":{"build":"parcel build","lint":"eslint .","fix-lint":"eslint --fix .","dev":"parcel watch","test":"vitest run","clean":"rm -rf dist .parcel-cache","docs":"typedoc","docs:serve":"typedoc && npx serve docs -l 8080","docs:mkdocs":"typedoc && mkdocs serve","docs:build":"typedoc && mkdocs build","docs:setup":"./scripts/setup-docs.sh","wallet-cli":"node examples/wallet-cli.cjs"},"repository":{"type":"git","url":"git+ssh://git@gitlab.com/nexa/wallet-sdk-ts.git"},"keywords":["nexa","wallet","web3","crypto","dapp","walletcomms","walletsdk"],"contributors":[{"name":"Dolaned"},{"name":"Griffith"},{"name":"Vgrunner"},{"name":"myendy"}],"author":"Dolaned","license":"MIT","bugs":{"url":"https://gitlab.com/nexa/wallet-sdk-ts/issues"},"homepage":"https://gitlab.com/nexa/wallet-sdk-ts#readme","description":"Wallet SDK for the Nexa blockchain","devDependencies":{"@parcel/packager-ts":"^2.15.4","@parcel/transformer-typescript-types":"^2.15.4","@types/lodash-es":"^4.17.12","@types/node":"^22.13.1","eslint":"^9.20.1","parcel":"^2.15.4","typedoc":"^0.28.7","typedoc-plugin-markdown":"^4.7.0","typedoc-plugin-rename-defaults":"^0.7.3","typescript":"^5.8.3","typescript-eslint":"^8.24.1","vitest":"^3.0.8"},"targets":{"main":{"context":"node","outputFormat":"commonjs","distDir":"dist","isLibrary":true,"includeNodeModules":["lodash-es"]},"module":{"context":"node","outputFormat":"esmodule","distDir":"dist","isLibrary":true},"browser":{"context":"browser","outputFormat":"esmodule","distDir":"dist","isLibrary":true}},"dependencies":{"@vgrunner/electrum-cash":"^2.0.12","bip39":"^3.1.0","js-big-decimal":"^2.2.0","libnexa-ts":"^1.0.5","lodash-es":"^4.17.21","prompt-sync":"^4.2.0","wallet-comms-sdk":"^0.6.1"},"files":["dist"],"directories":{"test":"tests"},"@parcel/resolver-default":{"packageExports":true}}');
const $3cd8d0b72420af59$export$1f6f962b0b96558 = {
  WS: "ws",
  WSS: "wss",
  TCP: "tcp",
  TCP_TLS: "tcp_tls"
};
class $884ce55f1db7e177$export$ba81aefc89aef50c {
  constructor() {
  }
  /**
   * Get Rostum Server Version
   */
  async getVersion() {
    return await this.execute("server.version");
  }
  /**
   * Get the block tip of the network / chain we are currently connected to
   */
  async getBlockTip() {
    return await this.execute("blockchain.headers.tip");
  }
  /**
   * Get the nexa balance of an address without the token balances
   * @param address
   */
  async getBalance(address) {
    return await this.execute("blockchain.address.get_balance", address, "exclude_tokens");
  }
  /**
   * Get The transaction history for an address
   * @param address
   */
  async getTransactionHistory(address) {
    return await this.execute("blockchain.address.get_history", address);
  }
  /**
   * Get the block height or block has of when the address was first used
   * @param address
   */
  async getFirstUse(address) {
    return await this.execute("blockchain.address.get_first_use", address);
  }
  /**
   * Get a single transaction object
   * @param id
   * @param verbose
   */
  async getTransaction(id, verbose = true) {
    return await this.execute("blockchain.transaction.get", id, verbose);
  }
  /**
   * Get a single unspent output including group data
   * @param outpoint
   */
  async getUtxo(outpoint) {
    return await this.execute("blockchain.utxo.get", outpoint);
  }
  /**
   * Get Utxos only containing nexa information
   * @param address
   */
  async getNexaUtxos(address) {
    return await this.execute("blockchain.address.listunspent", address, "exclude_tokens");
  }
  /**
   * Get all the utxo's for a token at an address
   * @param address
   * @param token
   */
  async getTokenUtxos(address, token) {
    let listunspent = await this.execute("token.address.listunspent", address, null, token);
    return listunspent.unspent;
  }
  /**
   * Get the token balances for an address
   * @param address
   * @param token
   */
  async getTokensBalance(address, token) {
    if (token) return await this.execute("token.address.get_balance", address, null, token);
    return await this.execute("token.address.get_balance", address);
  }
  /**
   * Get the token genesis for a token
   * @param token
   */
  async getTokenGenesis(token) {
    return await this.execute("token.genesis.info", token);
  }
  /**
   * Subscribe to address call back notifications, handy for updating the user when they receive nexa or tokens in
   * their wallet
   * @param addresses
   * @param callback
   */
  async subscribeToAddresses(addresses, callback) {
    for (const addr of addresses) await this.client?.subscribe(callback, "blockchain.address.subscribe", addr);
  }
  /**
   * Unsubscribe from address notifications to prevent memory leaks
   * @param addresses
   * @param callback
   */
  async unsubscribeFromAddresses(addresses, callback) {
    for (const addr of addresses) await this.client?.unsubscribe(callback, "blockchain.address.subscribe", addr);
  }
  /**
   * Broadcast a presigned transaction hash
   * @param txHex
   */
  async broadcast(txHex) {
    return await this.execute("blockchain.transaction.broadcast", txHex);
  }
  /**
   * Get the latency of the server connection
   */
  async getLatency() {
    try {
      let start = Date.now();
      let res = await this.getBlockTip();
      if (res) return Date.now() - start;
      return 0;
    } catch {
      return 0;
    }
  }
  /**
   * Create initial connection with the rostrum server
   * @param netOrParams - Network identifier or RostrumParams object
   * @param params - RostrumParams object (for backward compatibility)
   * @param electrumClient - Optional pre-configured ElectrumClient instance
   */
  async connect(netOrParams, params, electrumClient) {
    try {
      let connectionParams;
      if (netOrParams && typeof netOrParams === "object" && "host" in netOrParams && "port" in netOrParams && "scheme" in netOrParams)
        connectionParams = netOrParams;
      else if (params)
        connectionParams = params;
      else {
        const network = netOrParams ? (0, $149c1bd638913645$export$2e8191f482a38ccd).get(netOrParams) : (0, $149c1bd638913645$export$2e8191f482a38ccd).mainnet;
        if (network === (0, $149c1bd638913645$export$2e8191f482a38ccd).mainnet) connectionParams = {
          host: "electrum.nexa.org",
          port: 20004,
          scheme: (0, $3cd8d0b72420af59$export$1f6f962b0b96558).WSS
        };
        else if (network === (0, $149c1bd638913645$export$2e8191f482a38ccd).testnet) connectionParams = {
          host: "testnet-electrum.nexa.org",
          port: 30004,
          scheme: (0, $3cd8d0b72420af59$export$1f6f962b0b96558).WSS
        };
        else
          connectionParams = {
            host: "localhost",
            port: 30004,
            scheme: (0, $3cd8d0b72420af59$export$1f6f962b0b96558).WS
          };
      }
      if (electrumClient) {
        this.client = electrumClient;
        if (this.client.connection.status == (0, ConnectionStatus).DISCONNECTED) await this.client.connect();
      } else {
        this.client = new (0, ElectrumClient)("com.nexa.wallet-sdk", "1.4.3", connectionParams.host, connectionParams.port, connectionParams.scheme, 3e4, 1e4, true);
        await this.client.connect();
      }
    } catch (e) {
      if (e instanceof Error) console.info(e.message);
      else console.error(e);
      throw e;
    }
  }
  /**
   * Disconnect from the rostrum server
   * @param force
   */
  async disconnect(force) {
    try {
      return await this.client.disconnect(force);
    } catch (e) {
      console.log(e);
      return false;
    }
  }
  /**
   * internal function to call commands against the rostrum API
   * @param method
   * @param parameters
   * @private
   */
  async execute(method, ...parameters) {
    let res = await this.client.request(method, ...parameters);
    if (res instanceof Error) throw res;
    return res;
  }
}
const $884ce55f1db7e177$export$eaa49f0478d81b9d = new $884ce55f1db7e177$export$ba81aefc89aef50c();
class $b76a3f2ef1862027$export$c54c8796e94a37a0 {
  get transactions() {
    return this._transactions;
  }
  constructor(_bip44Account) {
    this._tokenBalances = {};
    this._tokenAuthorities = {};
    this._transactions = /* @__PURE__ */ new Map();
    this._bip44Account = _bip44Account;
    this._balance = {
      confirmed: 0,
      unconfirmed: 0
    };
    this._tokenBalances = {};
    this._tokenAuthorities = {};
  }
  get balance() {
    return this._balance;
  }
  set balance(value) {
    this._balance = value;
  }
  get tokenBalances() {
    return this._tokenBalances;
  }
  set tokenBalances(value) {
    this._tokenBalances = value;
  }
  get tokenAuthorities() {
    return this._tokenAuthorities;
  }
  set tokenAuthorities(value) {
    this._tokenAuthorities = value;
  }
  async fetchAndClassifyTransactions(transactionAddress, fromHeight) {
    const transactions = await $6f559318d8845d29$export$a2ed4b531376a5a4([
      transactionAddress
    ], fromHeight ?? 0);
    const txPromises = Array.from(transactions.txs.values()).map((tx) => $6f559318d8845d29$export$9c6f4f51acbc89b9(tx, [
      transactionAddress
    ]));
    const txEntities = await Promise.all(txPromises);
    for (let txEntity of txEntities) this.transactions.set(txEntity.txId, txEntity);
    return this.transactions;
  }
}
class $448355556707518b$export$2e2bcd8739ae039 extends $b76a3f2ef1862027$export$c54c8796e94a37a0 {
  constructor(bip44Account, accountIndex, addressKey) {
    super(bip44Account);
    this._accountIndex = accountIndex;
    this._accountKey = addressKey;
  }
  // this is used in AccountStore.ts to get the key to be used in the map for this account
  getAccountStoreKey() {
    return String(this._bip44Account + "." + this._accountIndex);
  }
  getAccountType() {
    return $6f559318d8845d29$export$b8ca5fa4899cbfc7.DAPP_ACCOUNT;
  }
  getNewAddress() {
    return this._accountKey.address;
  }
  getNewChangeAddress() {
    return this.getNewAddress();
  }
  get accountIndexes() {
    return {
      rIndex: this._accountIndex,
      cIndex: 0
    };
  }
  get accountKeys() {
    return {
      receiveKeys: [
        this._accountKey
      ],
      changeKeys: []
      // Empty for single-key accounts
    };
  }
  async loadBalances() {
    const { balances, authorities } = await $6f559318d8845d29$export$e4fb0bc90aacba9e([
      this._accountKey
    ]);
    let tokenBalances = [
      this._accountKey
    ].map((k) => k.tokensBalance);
    super.balance = $6f559318d8845d29$export$a26005fb5b8d1e4a(balances);
    super.tokenBalances = $6f559318d8845d29$export$dec515296f176dbe(tokenBalances);
    super.tokenAuthorities = authorities;
  }
  getKeyFromAddress(address) {
    if (address !== this._accountKey.address) throw new Error(`Address ${address} does not belong to this account`);
    return this._accountKey;
  }
  async getTransactions(fromHeight, address) {
    const transactionAddress = address ?? this._accountKey.address;
    return this.fetchAndClassifyTransactions(transactionAddress, fromHeight);
  }
  getAddresses() {
    return [
      this._accountKey
    ];
  }
  hasChangeAddresses() {
    return false;
  }
  getPrimaryAddressKey() {
    return this._accountKey;
  }
}
class $5c605efdbcfd6698$export$2e2bcd8739ae039 extends $b76a3f2ef1862027$export$c54c8796e94a37a0 {
  constructor(bip44Account, accountIndexes, accountKeys) {
    super(bip44Account);
    if (accountIndexes.rIndex < 0) throw new Error(`Can not create nexa account with an rindex of ${accountIndexes.rIndex}. must be >= 0.`);
    if (accountIndexes.cIndex < 0) throw new Error(`Can not create nexa account with an cindex of ${accountIndexes.cIndex}. must be >= 0.`);
    this._accountIndexes = accountIndexes;
    this._accountKeys = accountKeys;
  }
  // this is used in AccountStore.ts to get the key to be used in the map for this account
  getAccountStoreKey() {
    return String(this._bip44Account);
  }
  getAccountType() {
    return $6f559318d8845d29$export$b8ca5fa4899cbfc7.NEXA_ACCOUNT;
  }
  getNewAddress() {
    return this._accountKeys.receiveKeys[this._accountKeys.receiveKeys.length - 1]?.address ?? "";
  }
  getNewChangeAddress() {
    return this._accountKeys.changeKeys[this._accountKeys.changeKeys.length - 1]?.address ?? "";
  }
  get accountIndexes() {
    return this._accountIndexes;
  }
  get accountKeys() {
    return this._accountKeys;
  }
  async loadBalances() {
    const { balances, authorities } = await $6f559318d8845d29$export$e4fb0bc90aacba9e(this._accountKeys.receiveKeys.concat(this._accountKeys.changeKeys));
    let tokenBalances = this._accountKeys.receiveKeys.concat(this._accountKeys.changeKeys).map((k) => k.tokensBalance);
    super.balance = $6f559318d8845d29$export$a26005fb5b8d1e4a(balances);
    super.tokenBalances = $6f559318d8845d29$export$dec515296f176dbe(tokenBalances);
    super.tokenAuthorities = authorities;
  }
  getKeyFromAddress(address) {
    const allKeys = this._accountKeys.receiveKeys.concat(this._accountKeys.changeKeys);
    const keyFound = allKeys.find((key) => key.address === address);
    return keyFound;
  }
  async getTransactions(fromHeight, address) {
    let receiveAddresses = this.accountKeys.receiveKeys.map((ak) => ak.address);
    let changeAddresses = this.accountKeys.changeKeys.map((ak) => ak.address);
    let allAddresses = receiveAddresses.concat(changeAddresses);
    if (address != null) {
      const transactions = await $6f559318d8845d29$export$a2ed4b531376a5a4([
        address
      ], fromHeight ?? 0);
      const txPromises2 = Array.from(transactions.txs.values()).map((tx) => $6f559318d8845d29$export$9c6f4f51acbc89b9(tx, allAddresses));
      const txEntities2 = await Promise.all(txPromises2);
      for (let txEntity of txEntities2) this.transactions.set(txEntity.txId, txEntity);
      return this.transactions;
    }
    let rTxs = $6f559318d8845d29$export$a2ed4b531376a5a4(receiveAddresses, fromHeight ?? 0);
    let cTxs = $6f559318d8845d29$export$a2ed4b531376a5a4(changeAddresses, fromHeight ?? 0);
    let [rData, cData] = await Promise.all([
      rTxs,
      cTxs
    ]);
    let txHistory = rData.txs;
    for (let tx of cData.txs.values()) txHistory.set(tx.tx_hash, tx);
    const txPromises = Array.from(txHistory.values()).map((tx) => $6f559318d8845d29$export$9c6f4f51acbc89b9(tx, allAddresses));
    const txEntities = await Promise.all(txPromises);
    for (let txEntity of txEntities) this.transactions.set(txEntity.txId, txEntity);
    return this.transactions;
  }
  getAddresses() {
    return this._accountKeys.receiveKeys.concat(this._accountKeys.changeKeys);
  }
  hasChangeAddresses() {
    return true;
  }
  getPrimaryAddressKey() {
    if (this._accountKeys.receiveKeys.length === 0) throw new Error("No receive keys available in account");
    return this._accountKeys.receiveKeys[0];
  }
}
class $ce8955c0465759ad$export$2e2bcd8739ae039 extends $b76a3f2ef1862027$export$c54c8796e94a37a0 {
  constructor(bip44Account, accountIndex, addressKey) {
    super(bip44Account);
    this._accountIndex = accountIndex;
    this._accountKey = addressKey;
  }
  // this is used in AccountStore.ts to get the key to be used in the map for this account
  getAccountStoreKey() {
    return String(this._bip44Account + "." + this._accountIndex);
  }
  getAccountType() {
    return $6f559318d8845d29$export$b8ca5fa4899cbfc7.VAULT_ACCOUNT;
  }
  getNewAddress() {
    return this._accountKey.address;
  }
  getNewChangeAddress() {
    return this.getNewAddress();
  }
  get accountIndexes() {
    return {
      rIndex: this._accountIndex,
      cIndex: 0
    };
  }
  get accountKeys() {
    return {
      receiveKeys: [
        this._accountKey
      ],
      changeKeys: []
      // Empty for single-key accounts
    };
  }
  async loadBalances() {
    const { balances, authorities } = await $6f559318d8845d29$export$e4fb0bc90aacba9e([
      this._accountKey
    ]);
    let tokenBalances = [
      this._accountKey
    ].map((k) => k.tokensBalance);
    super.balance = $6f559318d8845d29$export$a26005fb5b8d1e4a(balances);
    super.tokenBalances = $6f559318d8845d29$export$dec515296f176dbe(tokenBalances);
    super.tokenAuthorities = authorities;
  }
  getKeyFromAddress(address) {
    if (address !== this._accountKey.address) throw new Error(`Address ${address} does not belong to this account`);
    return this._accountKey;
  }
  async getTransactions(fromHeight, address) {
    const transactionAddress = address ?? this._accountKey.address;
    return this.fetchAndClassifyTransactions(transactionAddress, fromHeight);
  }
  getAddresses() {
    return [
      this._accountKey
    ];
  }
  hasChangeAddresses() {
    return false;
  }
  getPrimaryAddressKey() {
    return this._accountKey;
  }
}
const $d78972a39a5ae94f$export$8ba128bc85947a2a = 9223372036854775807n;
function $d78972a39a5ae94f$export$78d0476e8d098ba7() {
  return Math.floor(Date.now() / 1e3);
}
function $d78972a39a5ae94f$export$c8733ae29fb53302(arg) {
  return !arg || arg.length === 0;
}
function $59b5736a17e7320d$export$7f7cffd29bf2d96d(authFlags, permission) {
  if (authFlags > 0) return false;
  let flags = BigInt.asUintN(64, BigInt(authFlags));
  switch (permission) {
    case "authorise":
      return $a0743653d736276e$export$2e2bcd8739ae039.allowsRenew(flags);
    case "mint":
      return $a0743653d736276e$export$2e2bcd8739ae039.allowsMint(flags);
    case "melt":
      return $a0743653d736276e$export$2e2bcd8739ae039.allowsMelt(flags);
    case "rescript":
      return $a0743653d736276e$export$2e2bcd8739ae039.allowsRescript(flags);
    case "subgroup":
      return $a0743653d736276e$export$2e2bcd8739ae039.allowsSubgroup(flags);
    default:
      return false;
  }
}
function $59b5736a17e7320d$export$636fb0b03b94ac81(authFlags, withSubgroup = true) {
  if (authFlags > 0) return 0n;
  let flags = BigInt.asUintN(64, BigInt(authFlags));
  let newFlags = $a0743653d736276e$export$2e2bcd8739ae039.authFlags.AUTHORITY;
  if ($a0743653d736276e$export$2e2bcd8739ae039.allowsRenew(flags)) newFlags |= $a0743653d736276e$export$2e2bcd8739ae039.authFlags.BATON;
  if ($a0743653d736276e$export$2e2bcd8739ae039.allowsMint(flags)) newFlags |= $a0743653d736276e$export$2e2bcd8739ae039.authFlags.MINT;
  if ($a0743653d736276e$export$2e2bcd8739ae039.allowsMelt(flags)) newFlags |= $a0743653d736276e$export$2e2bcd8739ae039.authFlags.MELT;
  if ($a0743653d736276e$export$2e2bcd8739ae039.allowsRescript(flags)) newFlags |= $a0743653d736276e$export$2e2bcd8739ae039.authFlags.RESCRIPT;
  if ($a0743653d736276e$export$2e2bcd8739ae039.allowsSubgroup(flags) && withSubgroup) newFlags |= $a0743653d736276e$export$2e2bcd8739ae039.authFlags.SUBGROUP;
  return newFlags;
}
function $59b5736a17e7320d$export$c949c84578b9e236(authFlags) {
  if (authFlags > 0) return [];
  const permissions = [];
  const flags = BigInt.asUintN(64, BigInt(authFlags));
  if ($a0743653d736276e$export$2e2bcd8739ae039.allowsRenew(flags)) permissions.push("authorise");
  if ($a0743653d736276e$export$2e2bcd8739ae039.allowsMint(flags)) permissions.push("mint");
  if ($a0743653d736276e$export$2e2bcd8739ae039.allowsMelt(flags)) permissions.push("melt");
  if ($a0743653d736276e$export$2e2bcd8739ae039.allowsRescript(flags)) permissions.push("rescript");
  if ($a0743653d736276e$export$2e2bcd8739ae039.allowsSubgroup(flags)) permissions.push("subgroup");
  return permissions;
}
var $6f559318d8845d29$export$dcc1fb6ad5308e56 = /* @__PURE__ */ (function(TxTokenType) {
  TxTokenType[TxTokenType["NO_GROUP"] = 0] = "NO_GROUP";
  TxTokenType[TxTokenType["CREATE"] = 1] = "CREATE";
  TxTokenType[TxTokenType["MINT"] = 2] = "MINT";
  TxTokenType[TxTokenType["MELT"] = 3] = "MELT";
  TxTokenType[TxTokenType["RENEW"] = 4] = "RENEW";
  TxTokenType[TxTokenType["TRANSFER"] = 5] = "TRANSFER";
  return TxTokenType;
})({});
var $6f559318d8845d29$export$b8ca5fa4899cbfc7 = /* @__PURE__ */ (function(AccountType) {
  AccountType[AccountType["NEXA_ACCOUNT"] = 0] = "NEXA_ACCOUNT";
  AccountType[AccountType["VAULT_ACCOUNT"] = 1] = "VAULT_ACCOUNT";
  AccountType[AccountType["DAPP_ACCOUNT"] = 2] = "DAPP_ACCOUNT";
  return AccountType;
})({});
function $6f559318d8845d29$export$8d986bd2866fe6ab(address, network, type = $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToScriptTemplate) {
  return $92cd415860c918d9$export$2e2bcd8739ae039.isValid(address, network, type);
}
function $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, account) {
  return masterKey.deriveChild(account, true);
}
function $6f559318d8845d29$export$d6e8eb22902c6b88(accountKey, fromRIndex, rIndex, fromCIndex, cIndex) {
  if (fromRIndex < 0) throw new Error(`Can not generate keys with fromRIndex ${fromRIndex}. must be >= 0.`);
  if (fromCIndex < 0) throw new Error(`Can not generate keys with fromCIndex ${fromCIndex}. must be >= 0.`);
  let receive = accountKey.deriveChild(0, false);
  let change = accountKey.deriveChild(1, false);
  let rKeys = [], cKeys = [];
  for (let index = fromRIndex; index < rIndex; index++) {
    let k = receive.deriveChild(index, false);
    let addr = k.privateKey.toAddress().toString();
    rKeys.push({
      key: k,
      address: addr,
      balance: "0",
      tokensBalance: {}
    });
  }
  for (let index = fromCIndex; index < cIndex; index++) {
    let k = change.deriveChild(index, false);
    let addr = k.privateKey.toAddress().toString();
    cKeys.push({
      key: k,
      address: addr,
      balance: "0",
      tokensBalance: {}
    });
  }
  return {
    receiveKeys: rKeys,
    changeKeys: cKeys
  };
}
function $6f559318d8845d29$export$1e0ce394ebe84ca9(accountKey, rIndex) {
  let receive = accountKey.deriveChild(0, false);
  let k = receive.deriveChild(rIndex, false);
  let addr = k.privateKey.toAddress().toString();
  return {
    key: k,
    address: addr,
    balance: "0",
    tokensBalance: {}
  };
}
async function $6f559318d8845d29$var$discoverUsedAccountIndexes(deriveKey) {
  let lastUsed = -1, index = 0, toScan = 20;
  while (toScan > 0) {
    toScan--;
    let rAddr = deriveKey.deriveChild(index, false).privateKey.toAddress().toString();
    let isUsed = await $6f559318d8845d29$var$isAddressUsed(rAddr);
    if (isUsed) {
      lastUsed = index;
      toScan = 20;
    }
    index++;
  }
  return lastUsed;
}
async function $6f559318d8845d29$export$4aeb2c92e53ab137(accountKey) {
  let receiveKey = accountKey.deriveChild(0, false);
  let changeKey = accountKey.deriveChild(1, false);
  let rIndexPromise = $6f559318d8845d29$var$discoverUsedAccountIndexes(receiveKey);
  let cIndexPromise = $6f559318d8845d29$var$discoverUsedAccountIndexes(changeKey);
  let [rIndex, cIndex] = await Promise.all([
    rIndexPromise,
    cIndexPromise
  ]);
  let indexes = {
    rIndex,
    cIndex
  };
  return indexes;
}
async function $6f559318d8845d29$export$f421913908d4303e(masterKey) {
  let accounts = [];
  let index = 0;
  while (true) {
    const nexaAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, index);
    const indexes = await $6f559318d8845d29$export$4aeb2c92e53ab137(nexaAccountKey);
    if (indexes.rIndex < 0 && indexes.cIndex < 0) break;
    if (indexes.rIndex < 0) indexes.rIndex = 0;
    if (indexes.cIndex < 0) indexes.cIndex = 0;
    const nexaAccount = new $5c605efdbcfd6698$export$2e2bcd8739ae039(index, indexes, $6f559318d8845d29$export$d6e8eb22902c6b88(nexaAccountKey, indexes.rIndex + 1, indexes.rIndex + 20, indexes.cIndex + 1, indexes.cIndex + 20));
    await nexaAccount.loadBalances();
    accounts.push(nexaAccount);
    if (index == 0) index = 100;
    else index++;
  }
  if (accounts.length == 0) {
    let defaultNexaAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, 0);
    let defaultIndexes = {
      rIndex: 0,
      cIndex: 0
    };
    const defaultAccount = new $5c605efdbcfd6698$export$2e2bcd8739ae039(0, defaultIndexes, $6f559318d8845d29$export$d6e8eb22902c6b88(defaultNexaAccountKey, defaultIndexes.rIndex, defaultIndexes.rIndex + 20, defaultIndexes.cIndex, defaultIndexes.cIndex + 20));
    await defaultAccount.loadBalances();
    accounts.push(defaultAccount);
  }
  return accounts;
}
async function $6f559318d8845d29$var$findUsedVaultAccounts(masterKey) {
  let vaultAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, 1);
  let vaultChain = vaultAccountKey.deriveChild(0, false);
  return await $6f559318d8845d29$var$discoverUsedAccountIndexes(vaultChain);
}
async function $6f559318d8845d29$export$eb24265dd203eccb(masterKey) {
  let accounts = [];
  let vaultAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, 1);
  let lastUsedVaultIndex = await $6f559318d8845d29$var$findUsedVaultAccounts(masterKey);
  if (lastUsedVaultIndex < 0) lastUsedVaultIndex = 0;
  for (let index = 0; index <= lastUsedVaultIndex; index++) {
    const vaultAccount = new $ce8955c0465759ad$export$2e2bcd8739ae039(1, index, $6f559318d8845d29$export$1e0ce394ebe84ca9(vaultAccountKey, index));
    await vaultAccount.loadBalances();
    accounts.push(vaultAccount);
  }
  return accounts;
}
async function $6f559318d8845d29$var$findUsedDappAccounts(masterKey) {
  let dappAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, 2);
  let dappChain = dappAccountKey.deriveChild(0, false);
  return await $6f559318d8845d29$var$discoverUsedAccountIndexes(dappChain);
}
async function $6f559318d8845d29$export$e3d879d0e09f52c3(masterKey) {
  let accounts = [];
  let dappAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, 2);
  let lastUsedDappIndex = await $6f559318d8845d29$var$findUsedDappAccounts(masterKey);
  if (lastUsedDappIndex < 0) lastUsedDappIndex = 0;
  for (let index = 0; index <= lastUsedDappIndex; index++) {
    const dappAccount = new $448355556707518b$export$2e2bcd8739ae039(2, index, $6f559318d8845d29$export$1e0ce394ebe84ca9(dappAccountKey, index));
    await dappAccount.loadBalances();
    accounts.push(dappAccount);
  }
  return accounts;
}
async function $6f559318d8845d29$export$4e4f91181d6bd31c(masterKey) {
  let accounts = [];
  const nexaAccounts = await $6f559318d8845d29$export$f421913908d4303e(masterKey);
  const vaultAccounts = await $6f559318d8845d29$export$eb24265dd203eccb(masterKey);
  const dappAccounts = await $6f559318d8845d29$export$e3d879d0e09f52c3(masterKey);
  accounts = accounts.concat(nexaAccounts);
  accounts = accounts.concat(vaultAccounts);
  accounts = accounts.concat(dappAccounts);
  return accounts;
}
async function $6f559318d8845d29$var$isAddressUsed(address) {
  try {
    let firstUse = await (0, $884ce55f1db7e177$export$eaa49f0478d81b9d).getFirstUse(address);
    return firstUse.tx_hash && firstUse.tx_hash !== "";
  } catch (e) {
    if (e instanceof Error && e.message.includes("not found")) return false;
    throw e;
  }
}
async function $6f559318d8845d29$var$getKeyTokenBalanceAndAuthorities(address) {
  const tokensBalance = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokensBalance(address);
  const balance = {};
  const authorities = {};
  const allTokenIds = /* @__PURE__ */ new Set([
    ...Object.keys(tokensBalance.confirmed),
    ...Object.keys(tokensBalance.unconfirmed)
  ]);
  for (const tokenId of allTokenIds) {
    const confirmedAmount = tokensBalance.confirmed[tokenId] || 0;
    const unconfirmedAmount = tokensBalance.unconfirmed[tokenId] || 0;
    if (confirmedAmount !== 0 || unconfirmedAmount !== 0) balance[tokenId] = {
      confirmed: BigInt(confirmedAmount).toString(),
      unconfirmed: BigInt(unconfirmedAmount).toString()
    };
    try {
      const tokenUtxos = await (0, $884ce55f1db7e177$export$eaa49f0478d81b9d).getTokenUtxos(address, tokenId);
      if (tokenUtxos && tokenUtxos.length > 0) {
        const authUtxos = tokenUtxos.filter((utxo) => {
          const amount = parseInt(String(utxo.token_amount || "0"));
          return amount < 0;
        });
        if (authUtxos.length > 0) {
          const authoritiesWithPermissions = authUtxos.map((utxo) => ({
            ...utxo,
            permissions: (0, $59b5736a17e7320d$export$c949c84578b9e236)(parseInt(String(utxo.token_amount || "0"))),
            address
          }));
          authorities[tokenId] = authoritiesWithPermissions;
        }
      }
    } catch (error) {
      console.warn(`Error checking authorities for token ${tokenId} on address ${address}:`, error);
    }
  }
  return {
    balance,
    authorities
  };
}
async function $6f559318d8845d29$var$getAndUpdateAddressKeyBalance(key) {
  let balance = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getBalance(key.address);
  key.balance = (BigInt(balance.confirmed) + BigInt(balance.unconfirmed)).toString();
  const { balance: tokenBalance, authorities } = await $6f559318d8845d29$var$getKeyTokenBalanceAndAuthorities(key.address);
  key.tokensBalance = tokenBalance;
  return {
    balance,
    authorities
  };
}
async function $6f559318d8845d29$export$e4fb0bc90aacba9e(keys) {
  let promises = [];
  keys.forEach((key) => {
    promises.push($6f559318d8845d29$var$getAndUpdateAddressKeyBalance(key));
  });
  const results = await Promise.all(promises);
  const balances = results.map((r) => r.balance);
  const combinedAuthorities = {};
  results.forEach((result) => {
    Object.keys(result.authorities).forEach((tokenId) => {
      if (combinedAuthorities[tokenId]) combinedAuthorities[tokenId] = combinedAuthorities[tokenId].concat(result.authorities[tokenId]);
      else combinedAuthorities[tokenId] = result.authorities[tokenId];
    });
  });
  return {
    balances,
    authorities: combinedAuthorities
  };
}
function $6f559318d8845d29$export$a26005fb5b8d1e4a(balances) {
  let confirmed = new bigDecimal(0), unconfirmed = new bigDecimal(0);
  balances.forEach((b) => {
    confirmed = confirmed.add(new bigDecimal(b.confirmed));
    unconfirmed = unconfirmed.add(new bigDecimal(b.unconfirmed));
  });
  return {
    confirmed: confirmed.getValue(),
    unconfirmed: unconfirmed.getValue()
  };
}
function $6f559318d8845d29$export$dec515296f176dbe(balances) {
  let tokensBalance = {};
  balances.forEach((b) => {
    for (const key in b) if (tokensBalance[key]) {
      tokensBalance[key].confirmed = (BigInt(tokensBalance[key].confirmed) + BigInt(b[key].confirmed)).toString();
      tokensBalance[key].unconfirmed = (BigInt(tokensBalance[key].unconfirmed) + BigInt(b[key].unconfirmed)).toString();
    } else tokensBalance[key] = {
      confirmed: b[key].confirmed,
      unconfirmed: b[key].unconfirmed
    };
  });
  return tokensBalance;
}
async function $6f559318d8845d29$export$a2ed4b531376a5a4(addresses, fromHeight) {
  let index = 0, i = 0, data = /* @__PURE__ */ new Map(), maxHeight = fromHeight;
  for (let address of addresses) {
    i++;
    let txHistory = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTransactionHistory(address);
    if (txHistory && txHistory.length > 0) {
      index = i;
      for (let tx of txHistory) if (tx.height === 0 || tx.height > fromHeight) {
        maxHeight = Math.max(maxHeight, tx.height);
        data.set(tx.tx_hash, tx);
      }
    }
  }
  return {
    index,
    txs: data,
    lastHeight: maxHeight
  };
}
async function $6f559318d8845d29$export$ef13479e8d3251d7(accountType, masterKey) {
  if (accountType == 0) {
    let defaultNexaAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, 0);
    const defaultIndexes = await $6f559318d8845d29$export$4aeb2c92e53ab137(defaultNexaAccountKey);
    if (defaultIndexes.rIndex < 0 && defaultIndexes.cIndex < 0) return 0;
    else
      for (let index = 100; ; index++) {
        const nexaAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, index);
        const indexes = await $6f559318d8845d29$export$4aeb2c92e53ab137(nexaAccountKey);
        if (indexes.rIndex < 0 && indexes.cIndex < 0) return index;
      }
  } else if (accountType == 1) {
    const lastUsedVault = await $6f559318d8845d29$var$findUsedVaultAccounts(masterKey);
    return lastUsedVault + 1;
  } else if (accountType == 2) {
    const lastUsedDappAccount = await $6f559318d8845d29$var$findUsedDappAccounts(masterKey);
    return lastUsedDappAccount + 1;
  } else throw new Error("Can not get next account index. Invalid accountType.");
}
async function $6f559318d8845d29$export$9c6f4f51acbc89b9(txHistory, myAddresses) {
  let t = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTransaction(txHistory.tx_hash);
  let outputs = t.vout.filter((utxo) => !isNil(utxo.scriptPubKey.addresses));
  let isOutgoing = t.vin.length > 0 && myAddresses.includes(t.vin[0].addresses[0]);
  let isIncoming = !isOutgoing || outputs.every((utxo) => myAddresses.includes(utxo.scriptPubKey.addresses[0]));
  let isConfirmed = t.height > 0;
  let txEntry = {};
  txEntry.txId = t.txid;
  txEntry.txIdem = t.txidem;
  txEntry.height = isConfirmed ? t.height : 0;
  txEntry.time = isConfirmed ? t.time : $d78972a39a5ae94f$export$78d0476e8d098ba7();
  txEntry.fee = t.fee_satoshi;
  if (isOutgoing && isIncoming) {
    txEntry.state = "both";
    txEntry.value = "0";
    txEntry.payTo = "Payment to yourself";
  } else if (isIncoming) {
    txEntry.state = "incoming";
    let utxos = outputs.filter((utxo) => myAddresses.includes(utxo.scriptPubKey.addresses[0]));
    let amount = new bigDecimal(0);
    utxos.forEach((utxo) => {
      amount = amount.add(new bigDecimal(utxo.value_satoshi));
    });
    txEntry.value = amount.getValue();
    txEntry.payTo = utxos[0].scriptPubKey.addresses[0];
  } else if (isOutgoing) {
    txEntry.state = "outgoing";
    let utxos = outputs.filter((utxo) => !myAddresses.includes(utxo.scriptPubKey.addresses[0]));
    let amount = new bigDecimal(0);
    utxos.forEach((utxo) => {
      amount = amount.add(new bigDecimal(utxo.value_satoshi));
    });
    txEntry.value = amount.getValue();
    txEntry.payTo = utxos[0].scriptPubKey.addresses[0];
  }
  let [txType, txGroup, tokenAmount, extraGroup] = $6f559318d8845d29$var$classifyTokenTransaction(t.vin, outputs, txEntry.state, myAddresses);
  txEntry.txGroupType = txType;
  txEntry.token = txGroup;
  txEntry.tokenAmount = tokenAmount;
  txEntry.extraGroup = extraGroup;
  return txEntry;
}
function $6f559318d8845d29$var$classifyTokenTransaction(vin, vout, txState, myAddresses) {
  let groupInputs = vin.filter((input) => !$d78972a39a5ae94f$export$c8733ae29fb53302(input.group));
  let groupOutputs = vout.filter((output) => !$d78972a39a5ae94f$export$c8733ae29fb53302(output.scriptPubKey.group));
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(groupInputs) && $d78972a39a5ae94f$export$c8733ae29fb53302(groupOutputs)) return [
    0,
    "none",
    "0",
    "none"
  ];
  let myGroupInputs = groupInputs.filter((input) => myAddresses.includes(input.addresses[0]));
  let myGroupOutputs = groupOutputs.filter((output) => myAddresses.includes(output.scriptPubKey.addresses[0]));
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(myGroupInputs) && $d78972a39a5ae94f$export$c8733ae29fb53302(myGroupOutputs)) return [
    0,
    "none",
    "0",
    "none"
  ];
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(groupInputs)) {
    let group2 = myGroupOutputs.find((output) => BigInt(output.scriptPubKey.groupQuantity) < 0n)?.scriptPubKey.group ?? "none";
    return [
      1,
      group2,
      "0",
      "none"
    ];
  }
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(groupOutputs)) {
    if (txState === "incoming") return [
      0,
      "none",
      "0",
      "none"
    ];
    let inputs = myGroupInputs.filter((input) => BigInt(input.groupQuantity) > 0n);
    if (!$d78972a39a5ae94f$export$c8733ae29fb53302(inputs)) {
      let amount2 = new bigDecimal(0);
      inputs.forEach((utxo) => {
        amount2 = amount2.add(new bigDecimal(utxo.groupQuantity));
      });
      let group3 = inputs[0].group;
      let extraGroup2 = myGroupInputs.find((input) => BigInt(input.groupQuantity) < 0n && inputs[0].group != input.group)?.group ?? "none";
      return [
        3,
        group3,
        amount2.getValue(),
        extraGroup2
      ];
    }
    let group2 = myGroupInputs.find((input) => BigInt(input.groupQuantity) < 0n)?.group ?? "none";
    let extraGroup = myGroupInputs.find((input) => BigInt(input.groupQuantity) < 0n && group2 != input.group)?.group ?? "none";
    return [
      3,
      group2,
      "0",
      extraGroup
    ];
  }
  let tokenInputs = groupInputs.filter((input) => BigInt(input.groupQuantity) > 0n);
  let tokenOutputs = groupOutputs.filter((output) => BigInt(output.scriptPubKey.groupQuantity) > 0n);
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(tokenInputs) && $d78972a39a5ae94f$export$c8733ae29fb53302(tokenOutputs)) {
    let group2 = groupInputs.find((input) => BigInt(input.groupQuantity) < 0n)?.group ?? "none";
    let extraGroup = groupOutputs.find((output) => BigInt(output.scriptPubKey.groupQuantity) < 0n && group2 != output.scriptPubKey.group)?.scriptPubKey.group ?? "none";
    return [
      4,
      extraGroup !== "none" ? extraGroup : group2,
      "0",
      extraGroup !== "none" ? group2 : extraGroup
    ];
  }
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(tokenInputs)) {
    let group2 = tokenOutputs[0].scriptPubKey.group;
    let amount2 = new bigDecimal(0);
    tokenOutputs.forEach((utxo) => {
      amount2 = amount2.add(new bigDecimal(utxo.scriptPubKey.groupQuantity));
    });
    let extraGroup = groupInputs.find((input) => BigInt(input.groupQuantity) < 0n && group2 != input.group)?.group ?? "none";
    return [
      2,
      group2,
      amount2.getValue(),
      extraGroup
    ];
  }
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(tokenOutputs)) {
    let group2 = tokenInputs[0].group;
    let amount2 = new bigDecimal(0);
    tokenInputs.forEach((utxo) => {
      amount2 = amount2.add(new bigDecimal(utxo.groupQuantity));
    });
    let extraGroup = groupInputs.find((input) => BigInt(input.groupQuantity) < 0n && group2 != input.group)?.group ?? "none";
    return [
      3,
      group2,
      amount2.getValue(),
      extraGroup
    ];
  }
  let outQuantitySum = tokenOutputs.map((output) => BigInt(output.scriptPubKey.groupQuantity)).reduce((a, b) => a + b, 0n);
  let inQuantitySum = tokenInputs.map((input) => BigInt(input.groupQuantity)).reduce((a, b) => a + b, 0n);
  if (outQuantitySum > inQuantitySum) {
    let group2 = tokenOutputs[0].scriptPubKey.group;
    let extraGroup = groupInputs.find((input) => BigInt(input.groupQuantity) < 0n && group2 != input.group)?.group ?? "none";
    return [
      2,
      group2,
      (outQuantitySum - inQuantitySum).toString(),
      extraGroup
    ];
  }
  if (inQuantitySum > outQuantitySum) {
    let group2 = tokenInputs[0].group;
    let extraGroup = groupInputs.find((input) => BigInt(input.groupQuantity) < 0n && group2 != input.group)?.group ?? "none";
    return [
      3,
      group2,
      (inQuantitySum - outQuantitySum).toString(),
      extraGroup
    ];
  }
  let group = tokenOutputs[0].scriptPubKey.group;
  let amount = "";
  if (txState === "incoming") amount = tokenOutputs.filter((output) => myAddresses.includes(output.scriptPubKey.addresses[0])).map((output) => BigInt(output.scriptPubKey.groupQuantity)).reduce((a, b) => a + b, 0n).toString();
  else if (txState === "outgoing") amount = tokenOutputs.filter((output) => !myAddresses.includes(output.scriptPubKey.addresses[0])).map((output) => BigInt(output.scriptPubKey.groupQuantity)).reduce((a, b) => a + b, 0n).toString();
  else amount = "0";
  return [
    5,
    group,
    amount,
    "none"
  ];
}
class $441c371114e3ba96$export$94f569bf4eb0f6f6 {
  static getAllKeys(keys) {
    return keys.receiveKeys.concat(keys.changeKeys);
  }
  static getAllAddresses(keys) {
    return $441c371114e3ba96$export$94f569bf4eb0f6f6.getAllKeys(keys).map((key) => key.address);
  }
}
const $3e8a638e2275dab4$var$MAX_INPUTS_OUTPUTS = 250;
async function $3e8a638e2275dab4$export$afd979971a55acfc(txBuilder, keys, totalTxValue, options, spentOutpoints) {
  let rKeys = keys.receiveKeys.filter((k) => BigInt(k.balance) > 0n);
  let cKeys = keys.changeKeys.filter((k) => BigInt(k.balance) > 0n);
  let allKeys = rKeys.concat(cKeys);
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(allKeys)) throw new Error("Not enough Nexa balance.");
  let usedKeys = /* @__PURE__ */ new Map();
  let origAmount = options.isConsolidate ? 0 : Number(totalTxValue);
  for (let key of allKeys) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getNexaUtxos(key.address);
    for (let utxo of utxos) {
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      let input = {
        outpoint: utxo.outpoint_hash,
        address: key.address,
        satoshis: utxo.value,
        templateData: options.templateData
      };
      txBuilder.from(input);
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      if (!usedKeys.has(key.address)) usedKeys.set(key.address, key.key.privateKey);
      if (options.isConsolidate) {
        txBuilder.change(options.toChange ?? keys.receiveKeys[keys.receiveKeys.length - 1].address);
        if (txBuilder.transaction.inputs.length > $3e8a638e2275dab4$var$MAX_INPUTS_OUTPUTS) return Array.from(usedKeys.values());
      } else {
        let tx = txBuilder.transaction;
        if (tx.inputs.length > $3e8a638e2275dab4$var$MAX_INPUTS_OUTPUTS) throw new Error("Too many inputs. Consider consolidate transactions or reduce the send amount.");
        let unspent = tx.getUnspentValue();
        if (unspent < 0n) continue;
        if (unspent == 0n && options.feeFromAmount) {
          let txFee = tx.estimateRequiredFee();
          tx.updateOutputAmount(0, origAmount - txFee);
          return Array.from(usedKeys.values());
        }
        const changeAddress = options.toChange ?? (keys.changeKeys.length > 0 ? keys.changeKeys[keys.changeKeys.length - 1].address : keys.receiveKeys[keys.receiveKeys.length - 1].address);
        txBuilder.change(changeAddress);
        if (options.feeFromAmount) {
          let hasChange = tx.getChangeOutput();
          let txFee = tx.estimateRequiredFee();
          tx.updateOutputAmount(0, origAmount - txFee);
          if (!hasChange && tx.getChangeOutput()) {
            txFee = tx.estimateRequiredFee();
            tx.updateOutputAmount(0, origAmount - txFee);
          }
        }
        if (tx.getUnspentValue() < tx.estimateRequiredFee()) continue;
        return Array.from(usedKeys.values());
      }
    }
  }
  if (options.isConsolidate) {
    if (usedKeys.size > 0) return Array.from(usedKeys.values());
    throw new Error("Not enough Nexa balance.");
  }
  let err = {
    errorMsg: "Not enough Nexa balance.",
    amount: $05e660d5daa855e4$export$2e2bcd8739ae039.formatNEXA(txBuilder.transaction.outputs[0].value),
    fee: $05e660d5daa855e4$export$2e2bcd8739ae039.formatNEXA(txBuilder.transaction.estimateRequiredFee())
  };
  throw new Error(JSON.stringify(err));
}
async function $3e8a638e2275dab4$export$931e37acdaa22dcf(txBuilder, keys, token, outTokenAmount, spentOutpoints) {
  let allKeys = keys.receiveKeys.concat(keys.changeKeys);
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(allKeys)) throw new Error("Not enough token balance.");
  let usedKeys = /* @__PURE__ */ new Map();
  let inTokenAmount = 0n;
  for (let key of allKeys) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(key.address, token);
    for (let utxo of utxos) {
      if (utxo.token_amount < 0) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: key.address,
        satoshis: utxo.value,
        groupId: utxo.group,
        groupAmount: BigInt(utxo.token_amount)
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      inTokenAmount = inTokenAmount + BigInt(utxo.token_amount);
      if (!usedKeys.has(key.address)) usedKeys.set(key.address, key.key.privateKey);
      if (inTokenAmount > $d78972a39a5ae94f$export$8ba128bc85947a2a) throw new Error("Token inputs exceeded max amount. Consider sending in small chunks");
      if (txBuilder.transaction.inputs.length > $3e8a638e2275dab4$var$MAX_INPUTS_OUTPUTS) throw new Error("Too many inputs. Consider consolidating transactions or reduce the send amount.");
      if (inTokenAmount == outTokenAmount) return Array.from(usedKeys.values());
      if (inTokenAmount > outTokenAmount) {
        const tokenChangeAddress = keys.changeKeys.length > 0 ? keys.changeKeys[keys.changeKeys.length - 1].address : keys.receiveKeys[keys.receiveKeys.length - 1].address;
        txBuilder.to(tokenChangeAddress, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, inTokenAmount - outTokenAmount);
        return Array.from(usedKeys.values());
      }
    }
  }
  throw new Error("Not enough token balance");
}
async function $3e8a638e2275dab4$export$d7f2b844e1d59768(txBuilder, keys, opReturnData, network, spentOutpoints) {
  const allKeys = $441c371114e3ba96$export$94f569bf4eb0f6f6.getAllKeys(keys);
  let outpoint = "";
  let usedKeys = [];
  let signKey = void 0;
  for (let key of allKeys) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getNexaUtxos(key.address);
    for (let utxo of utxos) {
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: key.address,
        satoshis: utxo.value
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      if ($d78972a39a5ae94f$export$c8733ae29fb53302(outpoint)) {
        outpoint = utxo.outpoint_hash;
        let id = $a0743653d736276e$export$2e2bcd8739ae039.findGroupId(outpoint, Buffer$1.from(opReturnData, "hex"), $a0743653d736276e$export$2e2bcd8739ae039.authFlags.ACTIVE_FLAG_BITS);
        const groupId = new $92cd415860c918d9$export$2e2bcd8739ae039(id.hashBuffer, network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.GroupIdAddress).toString();
        txBuilder.to(keys.receiveKeys.at(-1).address, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, groupId, $a0743653d736276e$export$2e2bcd8739ae039.authFlags.ACTIVE_FLAG_BITS | id.nonce);
        signKey = key.key.privateKey;
        usedKeys.push(signKey);
        return usedKeys;
      }
    }
  }
  throw new Error("Not enough Nexa balance.");
}
async function $3e8a638e2275dab4$export$48a48877d6df17e9(txBuilder, keys, outpoint) {
  let utxo = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getUtxo(outpoint);
  let address = utxo.addresses[0];
  txBuilder.from({
    outpoint,
    address,
    satoshis: utxo.amount
  });
  let allKeys = $441c371114e3ba96$export$94f569bf4eb0f6f6.getAllKeys(keys);
  let addrKey = allKeys.find((k) => k.address === address);
  if (!addrKey) throw new Error("UTXO associated key not found in the wallet");
  return [
    addrKey.key.privateKey
  ];
}
async function $3e8a638e2275dab4$export$1dfa5d829fc95097(txBuilder, keys, token, perm, subgroup = "", subgroupAddr = "", quantity, spentOutpoints) {
  let allKeys = $441c371114e3ba96$export$94f569bf4eb0f6f6.getAllKeys(keys);
  for (let key of allKeys) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(key.address, token);
    for (let utxo of utxos) {
      if (!$59b5736a17e7320d$export$7f7cffd29bf2d96d(utxo.token_amount, perm)) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: key.address,
        satoshis: utxo.value
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      if (perm === "subgroup") {
        const subgroupQuantity = quantity ?? $59b5736a17e7320d$export$636fb0b03b94ac81(utxo.token_amount, false);
        txBuilder.to(subgroupAddr, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, subgroup, subgroupQuantity);
      }
      if ($a0743653d736276e$export$2e2bcd8739ae039.allowsRenew(BigInt.asUintN(64, BigInt(utxo.token_amount)))) {
        const authChangeAddress = keys.changeKeys.length > 0 ? keys.changeKeys[keys.changeKeys.length - 1].address : keys.receiveKeys[keys.receiveKeys.length - 1].address;
        txBuilder.to(authChangeAddress, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, $59b5736a17e7320d$export$636fb0b03b94ac81(utxo.token_amount));
      }
      return [
        key.key.privateKey
      ];
    }
  }
  throw new Error("The requested authority not found");
}
async function $3e8a638e2275dab4$export$fc6e64edb1452fc7(txBuilder, keys, token, amount, parentToken, spentOutpoints) {
  const privateKeys = [];
  const allKeys = $441c371114e3ba96$export$94f569bf4eb0f6f6.getAllKeys(keys);
  const authTokenId = parentToken || token;
  let mintAuthorityFound = false;
  for (let key of allKeys) {
    if (mintAuthorityFound) break;
    let authUtxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(key.address, authTokenId);
    for (let utxo of authUtxos) {
      if (!$59b5736a17e7320d$export$7f7cffd29bf2d96d(utxo.token_amount, "mint")) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: key.address,
        satoshis: utxo.value
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      const mintAddress = keys.receiveKeys[keys.receiveKeys.length - 1].address;
      txBuilder.to(mintAddress, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, amount);
      if ($a0743653d736276e$export$2e2bcd8739ae039.allowsRenew(BigInt.asUintN(64, BigInt(utxo.token_amount)))) {
        const authChangeAddress = keys.changeKeys.length > 0 ? keys.changeKeys[keys.changeKeys.length - 1].address : keys.receiveKeys[keys.receiveKeys.length - 1].address;
        txBuilder.to(authChangeAddress, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, authTokenId, $59b5736a17e7320d$export$636fb0b03b94ac81(utxo.token_amount));
      }
      privateKeys.push(key.key.privateKey);
      mintAuthorityFound = true;
      break;
    }
  }
  if (!mintAuthorityFound) throw new Error(`Mint authority not found for token ${authTokenId}`);
  return privateKeys;
}
async function $3e8a638e2275dab4$export$661377a8795b235c(txBuilder, keys, token, amount, parentToken, spentOutpoints) {
  const privateKeys = [];
  const allKeys = $441c371114e3ba96$export$94f569bf4eb0f6f6.getAllKeys(keys);
  const authTokenId = parentToken || token;
  let meltAuthorityFound = false;
  for (let key of allKeys) {
    if (meltAuthorityFound) break;
    let authUtxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(key.address, authTokenId);
    for (let utxo of authUtxos) {
      if (!$59b5736a17e7320d$export$7f7cffd29bf2d96d(utxo.token_amount, "melt")) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: key.address,
        satoshis: utxo.value
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      if ($a0743653d736276e$export$2e2bcd8739ae039.allowsRenew(BigInt.asUintN(64, BigInt(utxo.token_amount)))) {
        const authChangeAddress = keys.changeKeys.length > 0 ? keys.changeKeys[keys.changeKeys.length - 1].address : keys.receiveKeys[keys.receiveKeys.length - 1].address;
        txBuilder.to(authChangeAddress, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, authTokenId, $59b5736a17e7320d$export$636fb0b03b94ac81(utxo.token_amount));
      }
      privateKeys.push(key.key.privateKey);
      meltAuthorityFound = true;
      break;
    }
  }
  if (!meltAuthorityFound) throw new Error("Melt authority not found for token");
  let inTokenAmount = 0n;
  for (let key of allKeys) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(key.address, token);
    for (let utxo of utxos) {
      if (utxo.token_amount < 0) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: key.address,
        satoshis: utxo.value,
        groupId: utxo.group,
        groupAmount: BigInt(utxo.token_amount)
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      inTokenAmount += BigInt(utxo.token_amount);
      if (!privateKeys.includes(key.key.privateKey)) privateKeys.push(key.key.privateKey);
      if (inTokenAmount >= amount) {
        if (inTokenAmount > amount) {
          const changeAddress = keys.changeKeys.length > 0 ? keys.changeKeys[keys.changeKeys.length - 1].address : keys.receiveKeys[keys.receiveKeys.length - 1].address;
          txBuilder.to(changeAddress, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, inTokenAmount - amount);
        }
        return privateKeys;
      }
    }
  }
  throw new Error(`Not enough token balance to melt. Required: ${amount}, Available: ${inTokenAmount}`);
}
async function $3e8a638e2275dab4$export$28a843ca046a6b3f(txBuilder, keys, token, perms, toAddr, spentOutpoints) {
  let allKeys = $441c371114e3ba96$export$94f569bf4eb0f6f6.getAllKeys(keys);
  let usedKeys = [];
  let reqiredPerms = new Set(perms);
  reqiredPerms.add("authorise");
  for (let key of allKeys) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(key.address, token);
    for (let utxo of utxos) {
      if (utxo.token_amount > 0) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      let found = false;
      for (let perm of reqiredPerms) if ($59b5736a17e7320d$export$7f7cffd29bf2d96d(utxo.token_amount, perm)) {
        reqiredPerms.delete(perm);
        found = true;
      }
      if (!found) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: key.address,
        satoshis: utxo.value
      });
      usedKeys.push(key.key.privateKey);
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      const duplicateAddress = toAddr != null ? toAddr : keys.changeKeys.length > 0 ? keys.changeKeys[keys.changeKeys.length - 1].address : keys.receiveKeys[keys.receiveKeys.length - 1].address;
      txBuilder.to(duplicateAddress, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, $59b5736a17e7320d$export$636fb0b03b94ac81(utxo.token_amount));
      if (reqiredPerms.size === 0) return usedKeys;
    }
  }
  throw new Error("The required authorities not found");
}
class $329d65a0aed426f1$export$bba690fb5c12ba04 {
  /**
   * Creates a new TransactionCreator instance
   * @param tx Optional existing TransactionBuilder, hex string, or buffer
   */
  constructor(tx) {
    this._builder = [];
    this._totalValue = BigInt(0);
    this._network = $149c1bd638913645$export$2e8191f482a38ccd.mainnet;
    this._txOptions = {};
    this._spentOutpoints = /* @__PURE__ */ new Set();
    if (tx instanceof $bd99faf64de54a2c$export$2e2bcd8739ae039) this.transactionBuilder = tx;
    this.tokens = /* @__PURE__ */ new Set();
    this.transactionBuilder = new $bd99faf64de54a2c$export$2e2bcd8739ae039();
  }
  /**
   * Parse transaction from hex string with common logic
   * @param tx Transaction hex string
   * @returns This instance for chaining
   */
  parseTxHex(tx) {
    this.builder = [];
    this.builder.push(async () => {
      try {
        const txBuilder = new (0, $bd99faf64de54a2c$export$2e2bcd8739ae039)(tx);
        const newTxBuilder = new (0, $bd99faf64de54a2c$export$2e2bcd8739ae039)();
        const oldInputs = txBuilder.transaction.inputs;
        for (let i = 0; i < oldInputs.length; i++) {
          const input = oldInputs[i];
          const utxo = await (0, $884ce55f1db7e177$export$eaa49f0478d81b9d).getUtxo(input.outpoint.toString("hex"));
          const scriptPubkey = (0, $90f45db77a786f2b$export$2e2bcd8739ae039).fromHex(utxo.scriptpubkey);
          if (scriptPubkey.isScriptTemplateOut()) {
            const scriptSig = input.scriptSig;
            newTxBuilder.transaction.addInput(new (0, $6995bc57838749e2$export$2e2bcd8739ae039)({
              amount: input.amount,
              outpoint: input.outpoint.toString("hex"),
              scriptSig: input.scriptSig,
              templateData: {
                templateScript: (0, $9f918c10ad4fef51$export$2e2bcd8739ae039).isHashBuffer(scriptPubkey.getTemplateHash()) ? (0, $90f45db77a786f2b$export$2e2bcd8739ae039).fromBuffer(scriptSig.chunks[0].buf) : (0, $90f45db77a786f2b$export$2e2bcd8739ae039).empty(),
                constraintScript: (0, $9f918c10ad4fef51$export$2e2bcd8739ae039).isHashBuffer(scriptPubkey.getConstraintHash()) ? (0, $90f45db77a786f2b$export$2e2bcd8739ae039).fromBuffer(scriptSig.chunks[1].buf) : (0, $92c0719d4ab9ac45$export$393941f88fd16991).OP_FALSE
              },
              output: {
                type: input.type,
                value: utxo.amount,
                scriptPubKey: utxo.scriptpubkey
              }
            }));
          } else
            newTxBuilder.from({
              outpoint: input.outpoint.toString("hex"),
              satoshis: input.amount,
              address: utxo.addresses[0],
              scriptPubKey: utxo.scriptpubkey
            });
          await this.handleParsedInput(input, utxo, i);
        }
        newTxBuilder.transaction.outputs = txBuilder.transaction.outputs;
        this.transactionBuilder = newTxBuilder;
        await this.handleParsingComplete();
      } catch (error) {
        console.error("parseTxHex: Error parsing transaction:", error);
        throw error;
      }
    });
    return this;
  }
  /**
   * Hook for subclasses to handle individual parsed inputs
   * @param input The original input from the transaction
   * @param utxo UTXO data for this input
   * @param index Input index
   */
  async handleParsedInput(input, utxo, index) {
  }
  /**
   * Hook for subclasses to perform post-processing after parsing is complete
   */
  async handleParsingComplete() {
  }
  /**
   * Sets the network for this transaction
   * @param network Network name or Networkish object
   * @returns This instance for chaining
   */
  onNetwork(network) {
    this.network = $149c1bd638913645$export$2e8191f482a38ccd.get(network);
    return this;
  }
  /** Gets transaction options */
  get txOptions() {
    return this._txOptions;
  }
  /** Sets transaction options */
  set txOptions(value) {
    this._txOptions = value;
  }
  /** Gets the network for this transaction */
  get network() {
    return this._network;
  }
  /** Sets the network for this transaction */
  set network(value) {
    this._network = value;
  }
  /** Gets the builder function array */
  get builder() {
    return this._builder;
  }
  /** Sets the builder function array */
  set builder(value) {
    this._builder = value;
  }
  /** Gets the underlying transaction builder */
  get transactionBuilder() {
    return this._transactionBuilder;
  }
  /** Sets the underlying transaction builder */
  set transactionBuilder(value) {
    this._transactionBuilder = value;
  }
  /** Gets the set of token actions */
  get tokens() {
    return this._tokens;
  }
  /** Sets the set of token actions */
  set tokens(value) {
    this._tokens = value;
  }
  /** Gets the total NEXA value being sent */
  get totalValue() {
    return this._totalValue;
  }
  /** Sets the total NEXA value being sent */
  set totalValue(value) {
    this._totalValue = value;
  }
  /** Gets the set of spent outpoints */
  get spentOutpoints() {
    return this._spentOutpoints;
  }
  /**
   * Updates the spent outpoints set with current transaction inputs
   * @returns Set of outpoint hashes that are already spent
   */
  updateSpentOutpoints() {
    this._spentOutpoints.clear();
    for (const input of this.transactionBuilder.transaction.inputs) this._spentOutpoints.add(input.outpoint.toString("hex"));
    return this._spentOutpoints;
  }
  /**
   * Validates and creates a token action
   * @param toAddr Destination address
   * @param amount Amount to send
   * @param token Token ID
   * @param action Action type (mint, melt, send, etc.)
   * @param parent Optional parent token ID (for NFT/SFT minting)
   * @throws Error if validation fails
   */
  tokenAction(toAddr, amount, token, action, parent) {
    if (!$6f559318d8845d29$export$8d986bd2866fe6ab(toAddr, this.network) && !$6f559318d8845d29$export$8d986bd2866fe6ab(toAddr, this.network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash)) throw new Error("Invalid Address.");
    if (token && BigInt(amount) < 1n || !token && parseInt$1(amount) < $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT) throw new Error("The amount is too low.");
    if (token && BigInt(amount) > $d78972a39a5ae94f$export$8ba128bc85947a2a || !token && parseInt$1(amount) > $926e193f4c554367$export$2e2bcd8739ae039.MAX_MONEY) throw new Error("The amount is too high.");
    if (!$6f559318d8845d29$export$8d986bd2866fe6ab(token, this.network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.GroupIdAddress)) throw new Error("Invalid Token ID");
    if ($92cd415860c918d9$export$2e2bcd8739ae039.getOutputType(toAddr) === 0) throw new Error("Token must be sent to script template address");
    if (action !== "mint" && action !== "melt")
      this.transactionBuilder.to(toAddr, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, BigInt(amount));
    this.tokens.add({
      token,
      parentToken: parent,
      amount: BigInt(amount),
      action
    });
  }
  /**
   * Configures transaction to consolidate UTXOs to a single address
   * @param toAddr Address to consolidate funds to
   * @returns This instance for chaining
   */
  consolidate(toAddr) {
    this.builder.push(async () => {
      if (!$6f559318d8845d29$export$8d986bd2866fe6ab(toAddr, this.network) && !$6f559318d8845d29$export$8d986bd2866fe6ab(toAddr, this.network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash)) throw new Error("Invalid Address.");
      this._txOptions.isConsolidate = true;
      this._txOptions.toChange = toAddr;
    });
    return this;
  }
  /**
   * Configures transaction to deduct fee from the send amount
   * @returns This instance for chaining
   */
  feeFromAmount() {
    this.builder.push(async () => {
      this._txOptions.feeFromAmount = true;
    });
    return this;
  }
  /**
   * Adds a token send operation to the transaction
   * @param toAddr Destination address
   * @param amount Amount of tokens to send
   * @param token Token ID
   * @param dustAmount Optional dust amount for the output (defaults to Transaction.DUST_AMOUNT)
   * @returns This instance for chaining
   */
  sendToToken(toAddr, amount, token, dustAmount = $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT) {
    this.builder.push(async () => {
      if (!$6f559318d8845d29$export$8d986bd2866fe6ab(toAddr, this.network) && !$6f559318d8845d29$export$8d986bd2866fe6ab(toAddr, this.network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash)) throw new Error("Invalid Address.");
      if (BigInt(amount) < 1n) throw new Error("The amount is too low.");
      if (BigInt(amount) > $d78972a39a5ae94f$export$8ba128bc85947a2a) throw new Error("The amount is too high.");
      if (!$6f559318d8845d29$export$8d986bd2866fe6ab(token, this.network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.GroupIdAddress)) throw new Error("Invalid Token ID");
      if ($92cd415860c918d9$export$2e2bcd8739ae039.getOutputType(toAddr) === 0) throw new Error("Token must be sent to script template address");
      this.transactionBuilder.to(toAddr, dustAmount, token, BigInt(amount));
      this.tokens.add({
        token,
        amount: BigInt(amount),
        action: "send"
      });
    });
    return this;
  }
  /**
   * Adds a NEXA send operation to the transaction
   * @param toAddr Destination address
   * @param amount Amount of NEXA to send
   * @returns This instance for chaining
   */
  sendTo(toAddr, amount) {
    this.builder.push(async () => {
      if (!$6f559318d8845d29$export$8d986bd2866fe6ab(toAddr, this.network) && !$6f559318d8845d29$export$8d986bd2866fe6ab(toAddr, this.network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash)) throw new Error("Invalid Address.");
      this.transactionBuilder.to(toAddr, amount);
      this.totalValue = BigInt(this.totalValue + amount);
    });
    return this;
  }
  /**
   * Adds a token authority renewal operation
   * @param token Token ID to renew authority for
   * @param perms Permissions to renew
   * @param toAddr
   * @returns This instance for chaining
   */
  renewAuthority(token, perms, toAddr) {
    this.builder.push(async () => {
      if (toAddr != null) {
        if (!$6f559318d8845d29$export$8d986bd2866fe6ab(toAddr, this.network) && !$6f559318d8845d29$export$8d986bd2866fe6ab(toAddr, this.network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash)) throw new Error("Invalid Address.");
      }
      this.tokens.add({
        token,
        action: "renew",
        amount: BigInt($926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT),
        parentToken: void 0,
        extraData: {
          perms,
          address: toAddr
        }
      });
    });
    return this;
  }
  /**
   * Adds a token authority deletion operation
   * @param token Token ID to delete authority for
   * @param outpoint Outpoint of the authority to delete
   * @returns This instance for chaining
   */
  deleteAuthority(token, outpoint) {
    this.builder.push(async () => {
      this.tokens.add({
        token,
        action: "delete",
        amount: BigInt($926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT),
        parentToken: void 0,
        extraData: {
          outpoint
        }
      });
    });
    return this;
  }
  /**
   * Creates a legacy token (not implemented)
   * @returns This instance for chaining
   */
  legacyToken(name, ticker, decimals, docUrl, docHash) {
    this.builder.push(async () => {
      const opReturn = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildTokenDescriptionLegacy(ticker, name, docUrl, docHash, decimals);
      this.transactionBuilder.addData(opReturn, true);
      this.tokens.add({
        action: "group",
        amount: BigInt($926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT),
        extraData: {
          opReturnData: opReturn.toHex()
        }
      });
    });
    return this;
  }
  /**
   * Creates a legacy group (not implemented)
   * @returns This instance for chaining
   */
  legacyGroup(name, ticker, docUrl, docHash) {
    this.builder.push(async () => {
      const opReturn = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildTokenDescriptionLegacy(ticker, name, docUrl, docHash);
      this.transactionBuilder.addData(opReturn, true);
      this.tokens.add({
        action: "group",
        amount: BigInt($926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT),
        extraData: {
          opReturnData: opReturn.toHex()
        }
      });
    });
    return this;
  }
  /**
   * Creates a token with metadata
   * @param name Token name
   * @param ticker Token ticker symbol
   * @param decimals Number of decimal places
   * @param docUrl URL to token documentation
   * @param docHash Hash of token documentation
   * @returns This instance for chaining
   */
  token(name, ticker, decimals, docUrl, docHash) {
    this.builder.push(async () => {
      const opReturn = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildTokenDescription(ticker, name, docUrl, docHash, decimals);
      this.transactionBuilder.addData(opReturn, true);
      this.tokens.add({
        action: "group",
        amount: BigInt($926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT),
        extraData: {
          opReturnData: opReturn.toHex()
        }
      });
    });
    return this;
  }
  /**
   * Creates an NFT collection with metadata
   * @param name Collection name
   * @param ticker Collection ticker symbol
   * @param docUrl URL to collection documentation
   * @param docHash Hash of collection documentation
   * @returns This instance for chaining
   */
  collection(name, ticker, docUrl, docHash) {
    this.builder.push(async () => {
      const opReturn = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildNFTCollectionDescription(ticker, name, docUrl, docHash);
      this.transactionBuilder.addData(opReturn, true);
      this.tokens.add({
        action: "group",
        amount: BigInt($926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT),
        extraData: {
          opReturnData: opReturn.toHex()
        }
      });
    });
    return this;
  }
  /**
   * Creates an NFT within a collection
   * @param parent Parent collection token ID
   * @param zipUrl URL to NFT content ZIP file
   * @param zipHash Hash of NFT content ZIP file
   * @returns This instance for chaining
   */
  nft(parent, zipUrl, zipHash) {
    this.builder.push(async () => {
      let opReturn = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildNFTDescription(zipUrl, zipHash);
      this.transactionBuilder.addData(opReturn, true);
      const subGroupBuffer = $a0743653d736276e$export$2e2bcd8739ae039.generateSubgroupId(parent, zipHash);
      const subGroupAddress = new $92cd415860c918d9$export$2e2bcd8739ae039(subGroupBuffer, $149c1bd638913645$export$2e8191f482a38ccd.get(this.network) || $149c1bd638913645$export$2e8191f482a38ccd.mainnet, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.GroupIdAddress).toString();
      this.tokens.add({
        token: subGroupAddress,
        parentToken: parent,
        amount: BigInt($926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT),
        action: "subgroup",
        extraData: {
          quantity: 1n
        }
      });
    });
    return this;
  }
  /**
   * Creates an SFT (Semi-Fungible Token) within a collection with specified quantity
   * @param parent Parent collection token ID
   * @param zipUrl URL to SFT content ZIP file
   * @param zipHash Hash of SFT content ZIP file
   * @param quantity Quantity of SFTs to create
   * @returns This instance for chaining
   */
  sft(parent, zipUrl, zipHash, quantity) {
    this.builder.push(async () => {
      let opReturn = $fea109eb8128bf4c$export$2e2bcd8739ae039.buildNFTDescription(zipUrl, zipHash);
      this.transactionBuilder.addData(opReturn, true);
      const subGroupBuffer = $a0743653d736276e$export$2e2bcd8739ae039.generateSubgroupId(parent, zipHash);
      const subGroupAddress = new $92cd415860c918d9$export$2e2bcd8739ae039(subGroupBuffer, $149c1bd638913645$export$2e8191f482a38ccd.get(this.network) || $149c1bd638913645$export$2e8191f482a38ccd.mainnet, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.GroupIdAddress).toString();
      this.tokens.add({
        token: subGroupAddress,
        parentToken: parent,
        amount: BigInt($926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT),
        action: "subgroup",
        extraData: {
          quantity
        }
      });
    });
    return this;
  }
  /**
   * Adds an OP_RETURN output to the transaction
   * @param data Data to include in the OP_RETURN
   * @param isFullScript Whether the data is already a complete script
   * @returns This instance for chaining
   */
  addOpReturn(data, isFullScript = false) {
    this.builder.push(async () => {
      let script = isFullScript ? new $90f45db77a786f2b$export$2e2bcd8739ae039(data) : $fea109eb8128bf4c$export$2e2bcd8739ae039.buildDataOut(data);
      let output = new $98955c312257c252$export$2e2bcd8739ae039(0, script);
      this.transactionBuilder.transaction.addOutput(output);
    });
    return this;
  }
  /**
   * Adds nexa contract constraint to spending inputs
   * @param templateScript
   * @param constraintScript
   * @param visibleArgs
   * @param pubKey
   * @returns This instance for chaining
   */
  addContract(templateScript, constraintScript, visibleArgs, pubKey) {
    this.builder.push(async () => {
      this.txOptions.templateData = {
        publicKey: pubKey,
        templateScript,
        constraintScript,
        visibleArgs
      };
    });
    return this;
  }
  /**
   * Builds the transaction by executing all queued operations
   * @returns Promise resolving to the serialized transaction hex
   */
  async build() {
    for (const task of this.builder) await task();
    return this.transactionBuilder.transaction.serialize({
      disableAll: true
    });
  }
}
class $d71d9063d6876a10$export$2e2bcd8739ae039 extends $329d65a0aed426f1$export$bba690fb5c12ba04 {
  constructor(fromAccount, tx) {
    super(tx), this._keysToSign = [];
    this._account = fromAccount;
    this.validateAccount();
  }
  fromAccount(fromAccount) {
    this._account = fromAccount;
    return this;
  }
  parseTxHex(tx) {
    return super.parseTxHex(tx);
  }
  /**
   * Handle wallet-specific logic for each parsed input (find and store private keys)
   */
  async handleParsedInput(input, utxo, index) {
    const foundKey = this.findPrivateKeyFromAddress(utxo.addresses[0]);
    if (foundKey) this._keysToSign.push(foundKey.key.privateKey);
  }
  /**
   * Handle wallet-specific post-processing after parsing is complete
   */
  async handleParsingComplete() {
    if (this._keysToSign.length == 0) this._keysToSign.push(this._account.getPrimaryAddressKey().key.privateKey);
  }
  parseTxBuffer(tx) {
    this.builder = [];
    this.transactionBuilder = new $bd99faf64de54a2c$export$2e2bcd8739ae039(tx);
    const addresses = this._account.getAddresses();
    for (const addressKey of addresses) if (!this._keysToSign.includes(addressKey.key.privateKey)) this._keysToSign.push(addressKey.key.privateKey);
    if (this._keysToSign.length == 0) this._keysToSign.push(this._account.getPrimaryAddressKey().key.privateKey);
    return this;
  }
  mint(token, amount, parent) {
    this.builder.push(async () => {
      let toAddr = this._account.accountKeys.receiveKeys.at(-1).address;
      this.tokenAction(toAddr, amount, token, "mint", parent);
    });
    return this;
  }
  melt(token, amount, parent) {
    this.builder.push(async () => {
      let toAddr = this._account.accountKeys.receiveKeys.at(-1).address;
      this.tokenAction(toAddr, amount, token, "melt", parent);
    });
    return this;
  }
  populate() {
    this.validateAccount();
    this.builder.push(async () => {
      let tK = [];
      let nK = [];
      if (this.tokens.size > 0) for (const tokenAction of this.tokens) {
        if (tokenAction.action == "mint") tK = tK.concat(await $3e8a638e2275dab4$export$fc6e64edb1452fc7(this.transactionBuilder, this._account.accountKeys, tokenAction.token, tokenAction.amount, tokenAction.parentToken, this.spentOutpoints));
        else if (tokenAction.action == "melt") tK = tK.concat(await $3e8a638e2275dab4$export$661377a8795b235c(this.transactionBuilder, this._account.accountKeys, tokenAction.token, tokenAction.amount, tokenAction.parentToken, this.spentOutpoints));
        else if (tokenAction.action == "group") tK = tK.concat(await $3e8a638e2275dab4$export$d7f2b844e1d59768(this.transactionBuilder, this._account.accountKeys, tokenAction.extraData?.opReturnData, this.network, this.spentOutpoints));
        else if (tokenAction.action == "subgroup") tK = tK.concat(await $3e8a638e2275dab4$export$1dfa5d829fc95097(this.transactionBuilder, this._account.accountKeys, tokenAction.parentToken, "subgroup", tokenAction.token, this._account.accountKeys.receiveKeys.at(-1).address, tokenAction.extraData?.quantity, this.spentOutpoints));
        else if (tokenAction.action == "renew") tK = tK.concat(await $3e8a638e2275dab4$export$28a843ca046a6b3f(this.transactionBuilder, this._account.accountKeys, tokenAction.token, tokenAction.extraData.perms, tokenAction.extraData.address, this.spentOutpoints));
        else if (tokenAction.action == "delete") tK = tK.concat(await $3e8a638e2275dab4$export$48a48877d6df17e9(this.transactionBuilder, this._account.accountKeys, tokenAction.extraData.outpoint));
        else tK = tK.concat(await $3e8a638e2275dab4$export$931e37acdaa22dcf(this.transactionBuilder, this._account.accountKeys, tokenAction.token, tokenAction.amount, this.spentOutpoints));
        this._keysToSign.concat(tK);
      }
      nK = nK.concat(await $3e8a638e2275dab4$export$afd979971a55acfc(this.transactionBuilder, this._account.accountKeys, this.totalValue, this.txOptions, this.spentOutpoints));
      this._keysToSign = tK.concat(nK);
    });
    return this;
  }
  sign() {
    this.builder.push(async () => {
      const inputs = this.transactionBuilder.transaction.inputs;
      for (let inputIndex = 0; inputIndex < inputs.length; inputIndex++) {
        const input = inputs[inputIndex];
        const analysis = this.analyzeScriptSig(input.scriptSig);
        if (analysis.strategy === "skip") {
          console.log(`Skipping input ${inputIndex} - no placeholder found`);
          continue;
        }
        const sighashType = analysis.sighashType || new $e50a883097cd2090$export$2e2bcd8739ae039();
        let signed = false;
        const allAddressKeys = this._account.getAddresses();
        for (const addressKey of allAddressKeys) try {
          const sig = (0, $2dc9a1945ba915b1$export$2e2bcd8739ae039).sign(this.transactionBuilder.transaction, inputIndex, sighashType, this.transactionBuilder.transaction.inputs[inputIndex].getSubscript(), addressKey.key.privateKey);
          const signatureBuffer = new (0, $6ebeca4bc214d833$export$2e2bcd8739ae039)({
            publicKey: addressKey.key.publicKey,
            sigType: sighashType,
            signature: sig,
            subscript: this.transactionBuilder.transaction.inputs[inputIndex].getSubscript(),
            inputIndex
          }).toTxSatisfier();
          if (analysis.strategy === "sign_all") this.transactionBuilder.signInput(inputIndex, addressKey.key.privateKey, sighashType);
          else if (analysis.strategy === "replace_placeholder" && analysis.placeholderIndex !== void 0) {
            if (input instanceof (0, $6995bc57838749e2$export$2e2bcd8739ae039) && analysis.satisfierElements && analysis.satisfierElements.length > 0) {
              const templateInput = input;
              const allSatisfierElements = [
                ...analysis.satisfierElements
              ];
              const relativeIndex = analysis.placeholderIndex - 2;
              allSatisfierElements.splice(relativeIndex, 0, signatureBuffer);
              this.transactionBuilder.transaction.inputs[inputIndex].scriptSig = this.buildScriptSig(templateInput.templateScript, templateInput.constraintScript, allSatisfierElements);
            } else if (input instanceof (0, $6995bc57838749e2$export$2e2bcd8739ae039)) {
              const templateInput = input;
              this.transactionBuilder.transaction.inputs[inputIndex].scriptSig = this.buildScriptSig(templateInput.templateScript, templateInput.constraintScript, [
                signatureBuffer
              ]);
            } else
              this.transactionBuilder.transaction.inputs[inputIndex].scriptSig = (0, $fea109eb8128bf4c$export$2e2bcd8739ae039).buildPublicKeyHashIn(addressKey.key.publicKey, sig);
          }
          signed = true;
          break;
        } catch (error) {
        }
      }
    });
    return this;
  }
  buildSatisfier(elements) {
    let script = new $90f45db77a786f2b$export$2e2bcd8739ae039();
    for (const element of elements) script = script.add(element);
    return script;
  }
  buildScriptSig(template, constraint, satisfierElements) {
    const satisfierScript = this.buildSatisfier(satisfierElements);
    return $fea109eb8128bf4c$export$2e2bcd8739ae039.buildScriptTemplateIn(template, constraint, satisfierScript);
  }
  /**
   * Check if a buffer is a 64-byte placeholder (all zeros)
   * @param buf - Buffer to check
   * @returns true if it's a 64-byte zero placeholder
   */
  isPlaceholder(buf) {
    if (!buf || buf.length < 64) return false;
    const placeholderBytes = Buffer$1.alloc(64, 0);
    return buf.subarray(0, 64).equals(placeholderBytes);
  }
  /**
   * Extract sighash type from placeholder buffer (bytes after the 64-byte placeholder)
   * @param buf - Buffer that may contain sighash type after placeholder
   * @returns SighashType or null if using default SIGHASH_ALL (empty sighash = 0)
   */
  extractSighashFromPlaceholder(buf) {
    if (buf.length <= 64)
      return $e50a883097cd2090$export$2e2bcd8739ae039.ALL;
    const sighashBytes = buf.subarray(64);
    if (sighashBytes.length === 0) return $e50a883097cd2090$export$2e2bcd8739ae039.ALL;
    const flagByte = sighashBytes[0];
    const inputType = flagByte >> 4 & 15;
    const outputType = flagByte & 15;
    const sighashType = new $e50a883097cd2090$export$2e2bcd8739ae039();
    let byteIndex = 1;
    switch (inputType) {
      case 0:
        sighashType.inType = 0;
        break;
      case 1:
        sighashType.inType = 1;
        if (byteIndex < sighashBytes.length) {
          sighashType.inData = [
            sighashBytes[byteIndex]
          ];
          byteIndex++;
        }
        break;
      case 2:
        sighashType.inType = 2;
        break;
      default:
        sighashType.inType = 0;
    }
    switch (outputType) {
      case 0:
        sighashType.outType = 0;
        break;
      case 1:
        sighashType.outType = 1;
        if (byteIndex < sighashBytes.length) {
          sighashType.outData = [
            sighashBytes[byteIndex]
          ];
          byteIndex++;
        }
        break;
      case 2:
        sighashType.outType = 2;
        const outData = [];
        if (byteIndex < sighashBytes.length) {
          outData.push(sighashBytes[byteIndex]);
          byteIndex++;
        }
        if (byteIndex < sighashBytes.length) {
          outData.push(sighashBytes[byteIndex]);
          byteIndex++;
        }
        sighashType.outData = outData;
        break;
      default:
        sighashType.outType = 0;
    }
    return sighashType;
  }
  /**
   * Determine signing behavior based on scriptSig content
   * @param scriptSig - The scriptSig to analyze
   * @returns Object with signing strategy and sighash type
   */
  analyzeScriptSig(scriptSig) {
    const chunks = scriptSig.chunks;
    if (chunks.length === 0) return {
      strategy: "sign_all",
      sighashType: $e50a883097cd2090$export$2e2bcd8739ae039.ALL
    };
    if (chunks.length === 1) {
      const chunk = chunks[0];
      if (chunk.buf && this.isPlaceholder(chunk.buf)) {
        const sighashType = this.extractSighashFromPlaceholder(chunk.buf);
        return {
          strategy: "sign_all",
          sighashType
        };
      }
      return {
        strategy: "skip",
        sighashType: null
      };
    }
    if (chunks.length >= 3) {
      const satisfierElements = [];
      let placeholderIndex;
      let sighashType = null;
      for (let i = 2; i < chunks.length; i++) {
        const chunk = chunks[i];
        if (chunk.buf && this.isPlaceholder(chunk.buf)) {
          placeholderIndex = i;
          sighashType = this.extractSighashFromPlaceholder(chunk.buf);
        } else
          satisfierElements.push(chunk);
      }
      if (placeholderIndex !== void 0) return {
        strategy: "replace_placeholder",
        sighashType,
        placeholderIndex,
        satisfierElements
      };
    }
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      if (chunk.buf && this.isPlaceholder(chunk.buf)) {
        const sighashType = this.extractSighashFromPlaceholder(chunk.buf);
        return {
          strategy: "replace_placeholder",
          sighashType,
          placeholderIndex: i
        };
      }
    }
    return {
      strategy: "skip",
      sighashType: null
    };
  }
  /**
   * Validates that the account has the necessary keys before performing operations
   * @throws Error if account or keys are not properly initialized
   */
  validateAccount() {
    if (!this._account) throw new Error("Account must be set before performing transactions");
    if (!this._account.accountKeys) throw new Error("Account keys are not initialized");
    if (!this._account.accountKeys.receiveKeys || this._account.accountKeys.receiveKeys.length === 0) throw new Error("No receive keys available in account");
  }
  findPrivateKeyFromAddress(addr) {
    const keys = this._account.getAddresses();
    return keys.find((key) => key.address === addr);
  }
}
class $7e26340ce0f64954$export$2e2bcd8739ae039 {
  /**
   * Creates a new AccountStore instance
   * Initializes an empty map to store accounts
   */
  constructor() {
    this._accounts = /* @__PURE__ */ new Map();
  }
  /**
   * Generates a unique store key for an account based on its type and index
   * @param accountType The type of account (DAPP, VAULT, or DEFAULT)
   * @param index The account index
   * @returns Unique string key for storing the account
   */
  getAccountStoreKey(accountType, index) {
    switch (accountType) {
      case $6f559318d8845d29$export$b8ca5fa4899cbfc7.DAPP_ACCOUNT:
        return String(accountType + "." + index);
      case $6f559318d8845d29$export$b8ca5fa4899cbfc7.VAULT_ACCOUNT:
        return String(accountType + "." + index);
      default:
        return String(index);
    }
  }
  /**
   * Creates a new account of the specified type
   * @param accountType Type of account to create (DAPP, VAULT, or DEFAULT)
   * @param masterKey Master HD private key for deriving account keys
   * @param forceNextIndex If true, forces the next sequential index regardless of blockchain usage
   * @returns Promise resolving to the created account
   */
  async createAccount(accountType, masterKey, forceNextIndex = false) {
    let nextIndex;
    if (forceNextIndex)
      nextIndex = await this.getNextSequentialIndex(accountType, masterKey);
    else
      nextIndex = await $6f559318d8845d29$export$ef13479e8d3251d7(accountType, masterKey);
    const accountStoreKey = this.getAccountStoreKey(accountType, nextIndex);
    const indexExists = this._accounts.get(String(accountStoreKey));
    if (indexExists) return indexExists;
    switch (accountType) {
      case $6f559318d8845d29$export$b8ca5fa4899cbfc7.DAPP_ACCOUNT:
        let dappAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, 2);
        const dAppAccount = new $448355556707518b$export$2e2bcd8739ae039(2, nextIndex, $6f559318d8845d29$export$1e0ce394ebe84ca9(dappAccountKey, nextIndex));
        await dAppAccount.loadBalances();
        this._accounts.set(dAppAccount.getAccountStoreKey(), dAppAccount);
        return dAppAccount;
      case $6f559318d8845d29$export$b8ca5fa4899cbfc7.VAULT_ACCOUNT:
        let vaultAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, 1);
        const vaultAccount = new $ce8955c0465759ad$export$2e2bcd8739ae039(1, nextIndex, $6f559318d8845d29$export$1e0ce394ebe84ca9(vaultAccountKey, nextIndex));
        await vaultAccount.loadBalances();
        this._accounts.set(vaultAccount.getAccountStoreKey(), vaultAccount);
        return vaultAccount;
      default:
        let nexaAccountKey = $6f559318d8845d29$export$b3a12d67e2f5f8c9(masterKey, nextIndex);
        const nexaAccountIndexes = {
          rIndex: 0,
          cIndex: 0
        };
        const nexaAccount = new $5c605efdbcfd6698$export$2e2bcd8739ae039(nextIndex, nexaAccountIndexes, $6f559318d8845d29$export$d6e8eb22902c6b88(nexaAccountKey, nexaAccountIndexes.rIndex + 1, nexaAccountIndexes.rIndex + 20, nexaAccountIndexes.cIndex + 1, nexaAccountIndexes.cIndex + 20));
        await nexaAccount.loadBalances();
        this._accounts.set(nexaAccount.getAccountStoreKey(), nexaAccount);
        return nexaAccount;
    }
  }
  /**
   * Finds the private key associated with a given address across all accounts
   * @param address The address to search for
   * @returns The AddressKey containing the private key, or null if not found
   */
  findKeyForAddress(address) {
    for (const [_, account] of this._accounts.entries()) {
      const allKeys = account.getAddresses();
      for (const key of allKeys) {
        if (key.address == address) return key;
      }
    }
    return null;
  }
  /**
   * Imports an existing account into the store
   * @param accountData The account data to import
   * @throws Error if an account with the same key already exists
   */
  importAccount(accountData) {
    let index = accountData.getAccountStoreKey();
    if (this._accounts.get(index)) throw Error("Account already exists!");
    this._accounts.set(String(index), accountData);
  }
  /**
   * Exports account data by index
   * @param accountIndex The account index to export
   * @returns The account data
   * @throws Error if the account doesn't exist
   */
  exportAccount(accountIndex) {
    if (!this._accounts.get(accountIndex)) throw Error("Cannot find account!");
    return this._accounts.get(accountIndex);
  }
  /**
   * Removes an account from the store
   * @param accountIndex The account index to remove
   * @throws Error if the account doesn't exist
   */
  removeAccount(accountIndex) {
    if (!this._accounts.get(accountIndex)) throw Error("Cannot find account!");
    this._accounts.delete(accountIndex);
  }
  /**
   * Returns all accounts in the store
   * @returns Map of account store keys to BaseAccount objects
   */
  listAccounts() {
    return this._accounts;
  }
  /**
   * Retrieves a specific account by its index
   * @param index The account index to retrieve
   * @returns The account if found, undefined otherwise
   */
  getAccount(index) {
    return this._accounts.get(index);
  }
  /**
   * Retrieves all accounts of a specific type
   * @param accountType The type of accounts to retrieve
   * @returns Array of accounts matching the specified type
   */
  getAccountsByType(accountType) {
    const accounts = [];
    for (const [key, account] of this._accounts)
      switch (accountType) {
        case $6f559318d8845d29$export$b8ca5fa4899cbfc7.DAPP_ACCOUNT:
          if (key.startsWith("2.")) accounts.push(account);
          break;
        case $6f559318d8845d29$export$b8ca5fa4899cbfc7.VAULT_ACCOUNT:
          if (key.startsWith("1.")) accounts.push(account);
          break;
        case $6f559318d8845d29$export$b8ca5fa4899cbfc7.NEXA_ACCOUNT:
          if (!key.includes(".")) accounts.push(account);
          break;
      }
    return accounts;
  }
  /**
   * Gets the next sequential index for an account type, considering both blockchain
   * discovery and accounts already in the store
   * @param accountType The account type to get the next index for
   * @param masterKey Master HD private key for blockchain discovery
   * @returns Promise resolving to the next safe sequential index
   */
  async getNextSequentialIndex(accountType, masterKey) {
    const discoveryIndex = await $6f559318d8845d29$export$ef13479e8d3251d7(accountType, masterKey);
    const storeBasedIndex = this.getNextStoreIndex(accountType);
    return Math.max(discoveryIndex, storeBasedIndex);
  }
  /**
   * Gets the next index based only on accounts currently in the store
   * @param accountType The account type to check
   * @returns The next available index in the store
   */
  getNextStoreIndex(accountType) {
    const indexes = [];
    for (const [key, _] of this._accounts) switch (accountType) {
      case $6f559318d8845d29$export$b8ca5fa4899cbfc7.DAPP_ACCOUNT:
        if (key.startsWith("2.")) indexes.push(parseInt(key.split(".")[1]));
        break;
      case $6f559318d8845d29$export$b8ca5fa4899cbfc7.VAULT_ACCOUNT:
        if (key.startsWith("1.")) indexes.push(parseInt(key.split(".")[1]));
        break;
      case $6f559318d8845d29$export$b8ca5fa4899cbfc7.NEXA_ACCOUNT:
        if (!key.includes(".")) indexes.push(parseInt(key));
        break;
    }
    if (indexes.length === 0) return 0;
    return Math.max(...indexes) + 1;
  }
}
class $006d7f03de390713$export$2e2bcd8739ae039 {
  /**
   * Validate that a state condition is true
   * 
   * @param condition - The condition to validate
   * @param message - Error message to throw if condition is false
   * @throws {Error} If condition is false
   * 
   * @example
   * ```typescript
   * ValidationUtils.validateState(wallet.isInitialized, 'Wallet must be initialized');
   * ```
   */
  static validateState(condition, message) {
    if (!condition) throw new Error(`Invalid State: ${message}`);
  }
  /**
   * Validate that an argument condition is true
   * 
   * @param condition - The condition to validate
   * @param argumentName - Name of the argument being validated
   * @param message - Optional additional error message
   * @throws {Error} If condition is false
   * 
   * @example
   * ```typescript
   * ValidationUtils.validateArgument(
   *   typeof amount === 'number',
   *   'amount',
   *   'must be a number'
   * );
   * ```
   */
  static validateArgument(condition, argumentName, message = "") {
    if (!condition) throw new Error(`Invalid Argument: ${argumentName}. ${message}`);
  }
  /**
   * Validate that an argument is of the expected type
   * 
   * @param argument - The argument to validate
   * @param type - Expected type (string name or constructor function)
   * @param argumentName - Name of the argument being validated
   * @throws {TypeError} If argument is not of expected type
   * 
   * @example
   * ```typescript
   * ValidationUtils.validateArgumentType(buffer, 'Buffer', 'data');
   * ValidationUtils.validateArgumentType(wallet, Wallet, 'wallet');
   * ValidationUtils.validateArgumentType(amount, 'number', 'amount');
   * ```
   */
  static validateArgumentType(argument, type, argumentName) {
    argumentName = argumentName || "(unknown name)";
    if (isString(type)) {
      if (type === "Buffer") {
        if (!Buffer$1.isBuffer(argument)) throw new TypeError(`Invalid Argument for ${argumentName}, expected ${type} but got ${typeof argument}`);
      } else if (typeof argument !== type) throw new TypeError(`Invalid Argument for ${argumentName}, expected ${type} but got ${typeof argument}`);
    } else {
      if (!(argument instanceof type)) throw new TypeError(`Invalid Argument for ${argumentName}, expected ${type} but got ${typeof argument}`);
    }
  }
}
class $8265cc68049fe82c$export$2e2bcd8739ae039 {
  /**
   * Creates a new Wallet instance
   *
   * @param data - Optional wallet data:
   *   - undefined: Generate new random seed phrase
   *   - string: Use as BIP39 seed phrase
   *   - HDPrivateKey: Use as master key directly
   * @param network - Network name ('mainnet', 'testnet', 'regtest'). Defaults to 'mainnet'
   *
   * @example
   * ```typescript
   * // Create new wallet with random seed
   * const wallet = new Wallet();
   *
   * // Create from seed phrase
   * const wallet = new Wallet('abandon abandon abandon...');
   *
   * // Create from master key
   * const masterKey = HDPrivateKey.fromString('xprv...');
   * const wallet = new Wallet(masterKey);
   *
   * // Create on testnet
   * const wallet = new Wallet(undefined, 'testnet');
   * ```
   */
  constructor(data, network) {
    this._forceSequentialIndexing = false;
    this._network = $149c1bd638913645$export$2e8191f482a38ccd.get(network) ?? $149c1bd638913645$export$2e8191f482a38ccd.mainnet;
    this._accountStore = new $7e26340ce0f64954$export$2e2bcd8739ae039();
    if (isNil(data)) {
      this.phrase = srcExports.generateMnemonic(128, void 0, srcExports.wordlists.english);
      const seed = srcExports.mnemonicToSeedSync(this.phrase, "");
      const masterKey = $8fc74ca0a6995b3b$export$2e2bcd8739ae039.fromSeed(seed, this._network ?? $149c1bd638913645$export$2e8191f482a38ccd.mainnet);
      this.masterKey = masterKey.deriveChild(44, true).deriveChild(29223, true);
    } else if (data instanceof $8fc74ca0a6995b3b$export$2e2bcd8739ae039)
      this.masterKey = data.deriveChild(44, true).deriveChild(29223, true);
    else if (isString(data)) {
      $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(srcExports.validateMnemonic(data), "Invalid BIP39 seed phrase provided");
      this.phrase = data;
      const seed = srcExports.mnemonicToSeedSync(this.phrase, "");
      const masterKey = $8fc74ca0a6995b3b$export$2e2bcd8739ae039.fromSeed(seed, this._network ?? $149c1bd638913645$export$2e8191f482a38ccd.mainnet);
      this.masterKey = masterKey.deriveChild(44, true).deriveChild(29223, true);
    }
  }
  /**
   * Create a new wallet with a randomly generated seed phrase
   *
   * This is the recommended way to create a new wallet for first-time users.
   * The generated seed phrase should be securely stored by the user.
   *
   * @returns A new Wallet instance with a random 12-word seed phrase
   *
   * @example
   * ```typescript
   * const wallet = Wallet.create();
   * console.log(wallet.export().phrase); // Store this securely!
   * ```
   */
  static create() {
    return new $8265cc68049fe82c$export$2e2bcd8739ae039();
  }
  /**
   * Create a wallet from an existing BIP39 seed phrase
   *
   * Use this method to restore a wallet from a previously generated seed phrase.
   * The seed phrase should be a valid BIP39 mnemonic.
   *
   * @param phrase - The BIP39 seed phrase (12 or 24 words)
   * @param network - Optional network name ('mainnet', 'testnet', 'regtest')
   * @returns A new Wallet instance restored from the seed phrase
   * @throws {Error} If the seed phrase is invalid or not provided
   *
   * @example
   * ```typescript
   * const wallet = Wallet.fromSeedPhrase(
   *   'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
   *   'testnet'
   * );
   * ```
   */
  static fromSeedPhrase(phrase, network) {
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(isString(phrase), "seedphrase must be provided");
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(srcExports.validateMnemonic(phrase), "Invalid BIP39 seed phrase provided");
    return new $8265cc68049fe82c$export$2e2bcd8739ae039(phrase, network);
  }
  /**
   * Create a wallet from an extended private key (xpriv)
   *
   * Use this method to create a wallet from a master private key in extended format.
   * This is useful for advanced users who want to use a specific key derivation.
   *
   * @param xpriv - The extended private key string (starts with 'xprv')
   * @param network - Optional network name ('mainnet', 'testnet', 'regtest')
   * @returns A new Wallet instance using the provided master key
   * @throws {Error} If the private key is invalid or not provided
   *
   * @example
   * ```typescript
   * const wallet = Wallet.fromXpriv(
   *   'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
   * );
   * ```
   */
  static fromXpriv(xpriv, network) {
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(isString(xpriv), "private key must be provided");
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(xpriv.trim().length > 0, "private key cannot be empty");
    let masterKey;
    try {
      masterKey = (0, $8fc74ca0a6995b3b$export$2e2bcd8739ae039).fromString(xpriv);
    } catch (error) {
      throw new Error(`Invalid extended private key format: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
    return new $8265cc68049fe82c$export$2e2bcd8739ae039(masterKey, network);
  }
  /**
   * Initialize the wallet by discovering accounts and loading balances
   *
   * This method performs account discovery using the BIP44 derivation path
   * and scans for existing accounts with transaction history or balances.
   * Must be called before using the wallet's accounts.
   *
   * @returns Promise that resolves when initialization is complete
   *
   * @example
   * ```typescript
   * const wallet = Wallet.fromSeedPhrase('your seed phrase');
   * await wallet.initialize();
   *
   * // Now you can access discovered accounts
   * const accounts = wallet.accountStore.listAccounts();
   * ```
   */
  async initialize() {
    const walletAccounts = await $6f559318d8845d29$export$4e4f91181d6bd31c(this.masterKey);
    for (const account of walletAccounts) this._accountStore.importAccount(account);
  }
  /**
   * Create a new transaction builder for this wallet
   *
   * @param fromAccount - The account to send the transaction from
   * @param x - Optional existing transaction data:
   *   - TransactionBuilder: Use existing transaction builder
   *   - string: Parse from hex string
   *   - Buffer: Parse from binary buffer
   *   - undefined: Create new empty transaction
   * @returns A new WalletTransactionCreator instance
   *
   * @example
   * ```typescript
   * const account = wallet.accountStore.getAccount(0);
   * const tx = wallet.newTransaction(account)
   *   .to('nexa:address', 1000000) // 1 NEXA
   *   .sign();
   *
   * // Or from existing transaction hex
   * const tx = wallet.newTransaction(account, 'raw_tx_hex')
   *   .sign();
   * ```
   */
  newTransaction(fromAccount, x) {
    let tx;
    if (x instanceof $bd99faf64de54a2c$export$2e2bcd8739ae039) tx = new $d71d9063d6876a10$export$2e2bcd8739ae039(fromAccount, x);
    else if (isString(x)) tx = new $d71d9063d6876a10$export$2e2bcd8739ae039(fromAccount).parseTxHex(x);
    else if (isBuffer(x) && !isNil(x)) tx = new $d71d9063d6876a10$export$2e2bcd8739ae039(fromAccount).parseTxBuffer(x);
    else tx = new $d71d9063d6876a10$export$2e2bcd8739ae039(fromAccount);
    return tx.onNetwork(this._network);
  }
  /**
   * Create a new account for this wallet
   *
   * @param accountType - The type of account to create:
   *   - 'DefaultAccount': Standard account for general use
   *   - 'VaultAccount': Secured account with additional protection
   *   - 'DappAccount': Account optimized for dApp interactions
   * @returns Promise that resolves to the newly created account
   *
   * @example
   * ```typescript
   * const defaultAccount = await wallet.newAccount('DefaultAccount');
   * const vaultAccount = await wallet.newAccount('VaultAccount');
   * const dappAccount = await wallet.newAccount('DappAccount');
   * ```
   */
  async newAccount(accountType) {
    return await this.accountStore.createAccount(accountType, this.masterKey, this._forceSequentialIndexing);
  }
  /**
   * Broadcast a signed transaction to the Nexa network
   *
   * @param transaction - The signed transaction in hex format
   * @returns Promise that resolves to the transaction ID (txid)
   * @throws {Error} If the transaction is invalid or broadcast fails
   *
   * @example
   * ```typescript
   * const tx = wallet.newTransaction(account)
   *   .to('nexa:address', 1000000)
   *   .sign();
   *
   * const txId = await wallet.sendTransaction(tx.toHex());
   * console.log('Transaction sent:', txId);
   * ```
   */
  async sendTransaction(transaction) {
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(isString(transaction), "transaction must be present and valid");
    return $884ce55f1db7e177$export$eaa49f0478d81b9d.broadcast(transaction);
  }
  /**
   * Subscribe to address notifications for transaction updates
   *
   * This method allows you to monitor one or more addresses for incoming and outgoing transactions.
   * You can provide either a single address string or an array of addresses. The callback will be
   * invoked whenever there are updates to any of the monitored addresses.
   *
   * @param addresses - A single address string or array of addresses to monitor
   * @param callback - Function to call when address notifications are received
   * @returns Promise that resolves when subscription is established
   * @throws {Error} If addresses parameter is invalid or empty
   *
   * @example
   * ```typescript
   * // Subscribe to a single address
   * await wallet.subscribeToAddressNotifications(
   *   'nexa:address123',
   *   (notification) => {
   *     console.log('Address notification:', notification);
   *   }
   * );
   *
   * // Subscribe to multiple addresses
   * await wallet.subscribeToAddressNotifications(
   *   ['nexa:address1', 'nexa:address2', 'nexa:address3'],
   *   (notification) => {
   *     console.log('Address notification:', notification);
   *   }
   * );
   *
   * // Subscribe to all wallet addresses
   * const accounts = wallet.accountStore.listAccounts();
   * const addresses = accounts.flatMap(account =>
   *   account.getAddresses().map(addr => addr.address)
   * );
   * await wallet.subscribeToAddressNotifications(addresses, callback);
   * ```
   */
  async subscribeToAddressNotifications(addresses, callback) {
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(!isNil(addresses), "addresses parameter is required");
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(!isNil(callback), "callback function is required");
    let addressArray;
    if (isString(addresses)) addressArray = [
      addresses
    ];
    else if (isArray(addresses)) {
      $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(addresses.length > 0, "addresses array cannot be empty");
      addressArray = addresses;
    } else throw new Error("addresses must be a string or array of strings");
    return $884ce55f1db7e177$export$eaa49f0478d81b9d.subscribeToAddresses(addressArray, callback);
  }
  /**
   * Unsubscribe from address notifications to prevent memory leaks
   *
   * This method stops listening for notifications on the specified addresses.
   * It's important to call this method when you no longer need to monitor addresses
   * to prevent memory leaks from accumulating callback references.
   *
   * @param addresses - Single address string or array of address strings to unsubscribe from
   * @param callback - The exact same callback function used in subscribeToAddressNotifications
   *
   * @example
   * ```typescript
   * // Unsubscribe from a single address
   * await wallet.unsubscribeFromAddressNotifications(
   *     'nexa:nqtsq5g5jsdmqqywaqd82lhnnk3a8wqunjz6gtxdtavnnekc',
   *     myCallback
   * );
   *
   * // Unsubscribe from multiple addresses
   * await wallet.unsubscribeFromAddressNotifications(addresses, myCallback);
   * ```
   */
  async unsubscribeFromAddressNotifications(addresses, callback) {
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(!isNil(addresses), "addresses parameter is required");
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(!isNil(callback), "callback function is required");
    let addressArray;
    if (isString(addresses)) addressArray = [
      addresses
    ];
    else if (isArray(addresses)) {
      $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(addresses.length > 0, "addresses array cannot be empty");
      addressArray = addresses;
    } else throw new Error("addresses must be a string or array of strings");
    return $884ce55f1db7e177$export$eaa49f0478d81b9d.unsubscribeFromAddresses(addressArray, callback);
  }
  /**
   * Sign a message using a specific address from this wallet
   *
   * The message is signed using the private key associated with the given address.
   * This can be used for authentication or to prove ownership of an address.
   *
   * @param message - The message to sign
   * @param addressToUse - The address whose private key should sign the message
   * @returns The signature as a base64-encoded string
   * @throws {Error} If the address is not owned by this wallet
   *
   * @example
   * ```typescript
   * const account = wallet.accountStore.getAccount(0);
   * const address = account.getReceiveAddress();
   * const signature = wallet.signMessage('Hello World', address);
   * ```
   */
  signMessage(message, addressToUse) {
    let msg = new $62ed62398e988143$export$2e2bcd8739ae039(message);
    const addressKey = this.accountStore.findKeyForAddress(addressToUse);
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(!isNil(addressKey), "You dont own this private key");
    return msg.sign(addressKey?.key.privateKey);
  }
  /**
   * Verify a message signature against an address
   *
   * This method can verify signatures created by any address, not just addresses
   * owned by this wallet. It's useful for verifying messages from other parties.
   *
   * @param message - The original message that was signed
   * @param signature - The signature to verify (base64-encoded)
   * @param address - The address that supposedly signed the message
   * @returns true if the signature is valid, false otherwise
   * @throws {Error} If any parameters are missing or invalid
   *
   * @example
   * ```typescript
   * const isValid = wallet.verifyMessage(
   *   'Hello World',
   *   'signature_string',
   *   'nexa:address'
   * );
   * console.log('Signature valid:', isValid);
   * ```
   */
  verifyMessage(message, signature, address) {
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(!isNil(message), "message is required");
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(!isNil(signature), "signature is required");
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(!isNil(address), "address is required ");
    let msg = new $62ed62398e988143$export$2e2bcd8739ae039(message);
    const addressKey = this.accountStore.findKeyForAddress(address);
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(!isNil(addressKey), "You dont own this private key");
    return msg.verify(address, signature);
  }
  /**
   * Export the wallet data for backup or storage
   *
   * Returns an object containing the wallet's seed phrase, master key, and accounts.
   * This data can be used to restore the wallet later. The seed phrase should be
   * stored securely as it provides full access to the wallet.
   *
   * @returns Object containing wallet data
   * @property {string} phrase - The BIP39 seed phrase (if available)
   * @property {HDPrivateKey} masterKey - The master private key
   * @property {BaseAccount[]} accounts - Array of discovered accounts
   *
   * @example
   * ```typescript
   * const walletData = wallet.export();
   *
   * // Store the seed phrase securely
   * const seedPhrase = walletData.phrase;
   *
   * // Later, restore the wallet
   * const restoredWallet = Wallet.fromSeedPhrase(seedPhrase);
   * ```
   */
  export() {
    return {
      phrase: this.phrase,
      masterKey: this.masterKey,
      accounts: this._accountStore.listAccounts()
    };
  }
  /**
   * Get the account store for managing wallet accounts
   *
   * The account store provides methods to create, import, and manage accounts
   * within this wallet. Each account has its own set of addresses and keys.
   *
   * @returns The wallet's account store
   *
   * @example
   * ```typescript
   * const accountStore = wallet.accountStore;
   * const accounts = accountStore.listAccounts();
   * const firstAccount = accountStore.getAccount(0);
   * ```
   */
  get accountStore() {
    return this._accountStore;
  }
  /**
   * Get the network this wallet is operating on
   *
   * @returns The network object (mainnet, testnet, or regtest)
   *
   * @example
   * ```typescript
   * const network = wallet.network;
   * console.log('Network:', network.name);
   * ```
   */
  get network() {
    return this._network;
  }
  /**
   * Get the current sequential indexing setting
   *
   * @returns true if forcing sequential indexing, false if using discovery-based indexing
   *
   * @example
   * ```typescript
   * const isSequential = wallet.forceSequentialIndexing;
   * console.log('Sequential indexing:', isSequential);
   * ```
   */
  get forceSequentialIndexing() {
    return this._forceSequentialIndexing;
  }
  /**
   * Set whether to force sequential account indexing
   *
   * When enabled, new accounts will use sequential indexes (0, 1, 2, ...) regardless
   * of blockchain activity. This is useful for multi-user wallets where each user
   * needs a unique account even if they haven't used it yet.
   *
   * When disabled (default), account creation uses discovery-based indexing which
   * scans the blockchain for existing activity before assigning indexes.
   *
   * @param force - true to force sequential indexing, false for discovery-based
   *
   * @example
   * ```typescript
   * // Enable sequential indexing for multi-user scenarios
   * wallet.forceSequentialIndexing = true;
   *
   * // Create accounts - they'll be 2.0, 2.1, 2.2 regardless of usage
   * const alice = await wallet.newAccount(AccountType.DAPP_ACCOUNT);
   * const bob = await wallet.newAccount(AccountType.DAPP_ACCOUNT);
   * const charlie = await wallet.newAccount(AccountType.DAPP_ACCOUNT);
   *
   * // Disable for normal discovery-based indexing
   * wallet.forceSequentialIndexing = false;
   * ```
   */
  set forceSequentialIndexing(force) {
    this._forceSequentialIndexing = force;
  }
}
const $c03143e0cae56add$var$MAX_INPUTS_OUTPUTS = 250;
async function $c03143e0cae56add$export$20e004915450ed44(txBuilder, addresses, totalTxValue, options, spentOutpoints) {
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(addresses)) throw new Error("Not enough Nexa balance.");
  let usedAddresses = /* @__PURE__ */ new Set();
  let origAmount = options.isConsolidate ? 0 : Number(totalTxValue);
  for (let item of addresses) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getNexaUtxos(item.address);
    for (let utxo of utxos) {
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      let input = {
        outpoint: utxo.outpoint_hash,
        address: item.address,
        satoshis: utxo.value,
        templateData: options.templateData
      };
      txBuilder.from(input);
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      if (!usedAddresses.has(item.address)) usedAddresses.add(item.address);
      if (options.isConsolidate) {
        txBuilder.change(options.toChange ?? item.address);
        if (txBuilder.transaction.inputs.length > $c03143e0cae56add$var$MAX_INPUTS_OUTPUTS) return Array.from(usedAddresses.values());
      } else {
        let tx = txBuilder.transaction;
        if (tx.inputs.length > $c03143e0cae56add$var$MAX_INPUTS_OUTPUTS) throw new Error("Too many inputs. Consider consolidate transactions or reduce the send amount.");
        let unspent = tx.getUnspentValue();
        if (unspent < 0n) continue;
        if (unspent == 0n && options.feeFromAmount) {
          let txFee = tx.estimateRequiredFee();
          tx.updateOutputAmount(0, origAmount - txFee);
          return Array.from(usedAddresses.values());
        }
        txBuilder.change(options.toChange ?? item.address);
        if (options.feeFromAmount) {
          let hasChange = tx.getChangeOutput();
          let txFee = tx.estimateRequiredFee();
          tx.updateOutputAmount(0, origAmount - txFee);
          if (!hasChange && tx.getChangeOutput()) {
            txFee = tx.estimateRequiredFee();
            tx.updateOutputAmount(0, origAmount - txFee);
          }
        }
        if (tx.getUnspentValue() < tx.estimateRequiredFee()) continue;
        return Array.from(usedAddresses.values());
      }
    }
  }
  if (options.isConsolidate) {
    if (usedAddresses.size > 0) return Array.from(usedAddresses.values());
    throw new Error("Not enough Nexa balance.");
  }
  let err = {
    errorMsg: "Not enough Nexa balance.",
    amount: $05e660d5daa855e4$export$2e2bcd8739ae039.formatNEXA(Number(totalTxValue)),
    fee: $05e660d5daa855e4$export$2e2bcd8739ae039.formatNEXA(txBuilder.transaction.estimateRequiredFee())
  };
  throw new Error(JSON.stringify(err));
}
async function $c03143e0cae56add$export$49bc96b87058cba4(txBuilder, addresses, token, outTokenAmount, spentOutpoints) {
  if ($d78972a39a5ae94f$export$c8733ae29fb53302(addresses)) throw new Error("Not enough token balance.");
  let usedKeys = /* @__PURE__ */ new Set();
  let inTokenAmount = 0n;
  for (let item of addresses) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(item.address, token);
    for (let utxo of utxos) {
      if (utxo.token_amount < 0) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: item.address,
        satoshis: utxo.value,
        groupId: utxo.group,
        groupAmount: BigInt(utxo.token_amount)
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      inTokenAmount = inTokenAmount + BigInt(utxo.token_amount);
      if (!usedKeys.has(item.address)) usedKeys.add(item.address);
      if (inTokenAmount > $d78972a39a5ae94f$export$8ba128bc85947a2a) throw new Error("Token inputs exceeded max amount. Consider sending in small chunks");
      if (txBuilder.transaction.inputs.length > $c03143e0cae56add$var$MAX_INPUTS_OUTPUTS) throw new Error("Too many inputs. Consider consolidating transactions or reduce the send amount.");
      if (inTokenAmount == outTokenAmount) return Array.from(usedKeys.values());
      if (inTokenAmount > outTokenAmount) {
        txBuilder.to(item.address, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, inTokenAmount - outTokenAmount);
        return Array.from(usedKeys.values());
      }
    }
  }
  throw new Error("Not enough token balance");
}
async function $c03143e0cae56add$export$74e83de914f372c5(txBuilder, addresses, opReturnData, network, spentOutpoints) {
  let outpoint = "";
  let usedKeys = [];
  for (let item of addresses) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getNexaUtxos(item.address);
    for (let utxo of utxos) {
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: item.address,
        satoshis: utxo.value
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      if ($d78972a39a5ae94f$export$c8733ae29fb53302(outpoint) && !utxo.has_token) {
        outpoint = utxo.outpoint_hash;
        let id = $a0743653d736276e$export$2e2bcd8739ae039.findGroupId(outpoint, Buffer$1.from(opReturnData, "hex"), $a0743653d736276e$export$2e2bcd8739ae039.authFlags.ACTIVE_FLAG_BITS);
        const groupId = new $92cd415860c918d9$export$2e2bcd8739ae039(id.hashBuffer, network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.GroupIdAddress).toString();
        txBuilder.to(item.address, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, groupId, $a0743653d736276e$export$2e2bcd8739ae039.authFlags.ACTIVE_FLAG_BITS | id.nonce);
        usedKeys.push(item.address);
        return usedKeys;
      }
    }
  }
  throw new Error("Not enough Nexa balance.");
}
async function $c03143e0cae56add$export$1eb54f2f084fd3c6(txBuilder, addresses, outpoint) {
  let utxo = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getUtxo(outpoint);
  let address = utxo.addresses[0];
  txBuilder.from({
    outpoint,
    address,
    satoshis: utxo.amount
  });
  let addrKey = addresses.find((k) => k.address === address);
  if (!addrKey) throw new Error("UTXO associated key not found in the wallet");
  return [
    addrKey.address
  ];
}
async function $c03143e0cae56add$export$d7c9c386067a6463(txBuilder, addresses, token, perm, subgroup = "", subgroupAddr = "", quantity, spentOutpoints) {
  for (let item of addresses) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(item.address, token);
    for (let utxo of utxos) {
      if (!$59b5736a17e7320d$export$7f7cffd29bf2d96d(utxo.token_amount, perm)) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: item.address,
        satoshis: utxo.value
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      if (perm === "subgroup") {
        const subgroupQuantity = quantity ?? $59b5736a17e7320d$export$636fb0b03b94ac81(utxo.token_amount, false);
        txBuilder.to(subgroupAddr, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, subgroup, subgroupQuantity);
      }
      if ($a0743653d736276e$export$2e2bcd8739ae039.allowsRenew(BigInt.asUintN(64, BigInt(utxo.token_amount)))) txBuilder.to(item.address, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, $59b5736a17e7320d$export$636fb0b03b94ac81(utxo.token_amount));
      return [
        item.address
      ];
    }
  }
  throw new Error("The requested authority not found");
}
async function $c03143e0cae56add$export$91f9f23df90683cc(txBuilder, addresses, token, amount, parentToken, spentOutpoints) {
  const usedAddresses = [];
  const authTokenId = parentToken || token;
  let mintAuthorityFound = false;
  for (let item of addresses) {
    if (mintAuthorityFound) break;
    let authUtxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(item.address, authTokenId);
    for (let utxo of authUtxos) {
      if (!$59b5736a17e7320d$export$7f7cffd29bf2d96d(utxo.token_amount, "mint")) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: item.address,
        satoshis: utxo.value
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      txBuilder.to(item.address, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, amount);
      if ($a0743653d736276e$export$2e2bcd8739ae039.allowsRenew(BigInt.asUintN(64, BigInt(utxo.token_amount)))) txBuilder.to(item.address, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, authTokenId, $59b5736a17e7320d$export$636fb0b03b94ac81(utxo.token_amount));
      usedAddresses.push(item.address);
      mintAuthorityFound = true;
      break;
    }
  }
  if (!mintAuthorityFound) throw new Error(`Mint authority not found for token ${authTokenId}`);
  return usedAddresses;
}
async function $c03143e0cae56add$export$cfda880a425a2203(txBuilder, addresses, token, amount, parentToken, spentOutpoints) {
  const usedAddresses = [];
  const authTokenId = parentToken || token;
  let meltAuthorityFound = false;
  for (let item of addresses) {
    if (meltAuthorityFound) break;
    let authUtxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(item.address, authTokenId);
    for (let utxo of authUtxos) {
      if (!$59b5736a17e7320d$export$7f7cffd29bf2d96d(utxo.token_amount, "melt")) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: item.address,
        satoshis: utxo.value
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      if ($a0743653d736276e$export$2e2bcd8739ae039.allowsRenew(BigInt.asUintN(64, BigInt(utxo.token_amount)))) txBuilder.to(item.address, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, authTokenId, $59b5736a17e7320d$export$636fb0b03b94ac81(utxo.token_amount));
      usedAddresses.push(item.address);
      meltAuthorityFound = true;
      break;
    }
  }
  if (!meltAuthorityFound) throw new Error("Melt authority not found for token");
  let inTokenAmount = 0n;
  for (let item of addresses) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(item.address, token);
    for (let utxo of utxos) {
      if (utxo.token_amount < 0) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: item.address,
        satoshis: utxo.value,
        groupId: utxo.group,
        groupAmount: BigInt(utxo.token_amount)
      });
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      inTokenAmount += BigInt(utxo.token_amount);
      if (!usedAddresses.includes(item.address)) usedAddresses.push(item.address);
      if (inTokenAmount >= amount) {
        if (inTokenAmount > amount) txBuilder.to(item.address, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, inTokenAmount - amount);
        return usedAddresses;
      }
    }
  }
  throw new Error(`Not enough token balance to melt. Required: ${amount}, Available: ${inTokenAmount}`);
}
async function $c03143e0cae56add$export$5c44e04d8c04c292(txBuilder, addresses, token, perms, toAddr, spentOutpoints) {
  let usedAddresses = [];
  let reqiredPerms = new Set(perms);
  reqiredPerms.add("authorise");
  for (let item of addresses) {
    let utxos = await $884ce55f1db7e177$export$eaa49f0478d81b9d.getTokenUtxos(item.address, token);
    for (let utxo of utxos) {
      if (utxo.token_amount > 0) continue;
      if (spentOutpoints && spentOutpoints.has(utxo.outpoint_hash)) continue;
      let found = false;
      for (let perm of reqiredPerms) if ($59b5736a17e7320d$export$7f7cffd29bf2d96d(utxo.token_amount, perm)) {
        reqiredPerms.delete(perm);
        found = true;
      }
      if (!found) continue;
      txBuilder.from({
        outpoint: utxo.outpoint_hash,
        address: item.address,
        satoshis: utxo.value
      });
      usedAddresses.push(item.address);
      if (spentOutpoints) spentOutpoints.add(utxo.outpoint_hash);
      txBuilder.to(toAddr != null ? toAddr : item.address, $926e193f4c554367$export$2e2bcd8739ae039.DUST_AMOUNT, token, $59b5736a17e7320d$export$636fb0b03b94ac81(utxo.token_amount));
      if (reqiredPerms.size === 0) return usedAddresses;
    }
  }
  throw new Error("The required authorities not found");
}
class $fab743d51c8bbe7e$export$2e2bcd8739ae039 extends $329d65a0aed426f1$export$bba690fb5c12ba04 {
  /**
   * Creates a new WatchOnlyTransactionCreator
   * @param tx Optional existing transaction builder or transaction data
   */
  constructor(tx) {
    super(tx), /** Addresses that need to be signed with (populated during transaction building) */
    this._addressesToSignWith = [], /** Available addresses for input selection and change */
    this._availableAddresses = [];
  }
  /**
   * Sets the source addresses for transaction inputs
   * @param address Single address string, array of addresses, or WatchOnlyAddress objects
   * @returns This instance for chaining
   */
  from(address) {
    if (isString(address)) {
      if (!$6f559318d8845d29$export$8d986bd2866fe6ab(address, this.network) && !$6f559318d8845d29$export$8d986bd2866fe6ab(address, this.network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash)) throw new Error("Invalid Address.");
      this._availableAddresses.push({
        address
      });
    } else if (Array.isArray(address))
      address.forEach((addr) => {
        if (isString(addr)) {
          if (!$6f559318d8845d29$export$8d986bd2866fe6ab(addr, this.network) && !$6f559318d8845d29$export$8d986bd2866fe6ab(addr, this.network, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2.PayToPublicKeyHash)) throw new Error("Invalid Address.");
          this._availableAddresses.push({
            address: addr
          });
        } else if (addr && typeof addr === "object" && "address" in addr)
          this._availableAddresses.push(addr);
      });
    else if (address.address != null)
      this._availableAddresses.push(address);
    return this;
  }
  /**
   * Adds a token minting operation to the transaction
   * @param token Token ID to mint
   * @param amount Amount to mint
   * @param toAddr Destination address for minted tokens
   * @param parent Optional parent token ID (for NFT/SFT minting)
   * @returns This instance for chaining
   */
  mint(token, amount, toAddr, parent) {
    this.builder.push(async () => {
      this.tokenAction(toAddr, amount, token, "mint", parent);
    });
    return this;
  }
  /**
   * Adds a token melting operation to the transaction
   * @param token Token ID to melt
   * @param amount Amount to melt
   * @param toAddr Destination address for change of melted tokens
   * @param parent Optional parent token ID (for NFT/SFT melting)
   * @returns This instance for chaining
   */
  melt(token, amount, toAddr, parent) {
    this.builder.push(async () => {
      this.tokenAction(toAddr, amount, token, "melt", parent);
    });
    return this;
  }
  /**
   * Populates the transaction with inputs and outputs based on the configured actions.
   * Handles different token operations (mint, melt, group creation, etc.) and
   * populates NEXA inputs for transaction fees.
   * @returns This instance for chaining
   */
  populate() {
    this.builder.push(async () => {
      let tokenAddresses = [];
      let nexaAddresses = [];
      if (this.tokens.size > 0) for (const tokenAction of this.tokens) {
        if (tokenAction.action == "mint")
          tokenAddresses = tokenAddresses.concat(await $c03143e0cae56add$export$91f9f23df90683cc(this.transactionBuilder, this._availableAddresses, tokenAction.token, tokenAction.amount, tokenAction.parentToken, this.spentOutpoints));
        else if (tokenAction.action == "melt")
          tokenAddresses = tokenAddresses.concat(await $c03143e0cae56add$export$cfda880a425a2203(this.transactionBuilder, this._availableAddresses, tokenAction.token, tokenAction.amount, tokenAction.parentToken, this.spentOutpoints));
        else if (tokenAction.action == "group")
          tokenAddresses = tokenAddresses.concat(await $c03143e0cae56add$export$74e83de914f372c5(this.transactionBuilder, this._availableAddresses, tokenAction.extraData?.opReturnData, this.network, this.spentOutpoints));
        else if (tokenAction.action == "subgroup")
          tokenAddresses = tokenAddresses.concat(await $c03143e0cae56add$export$d7c9c386067a6463(this.transactionBuilder, this._availableAddresses, tokenAction.parentToken, tokenAction.action, tokenAction.token, this._availableAddresses[0]?.address, tokenAction.extraData?.quantity, this.spentOutpoints));
        else if (tokenAction.action == "renew")
          tokenAddresses = tokenAddresses.concat(await $c03143e0cae56add$export$5c44e04d8c04c292(this.transactionBuilder, this._availableAddresses, tokenAction.token, tokenAction.extraData.perms, tokenAction.extraData?.address, this.spentOutpoints));
        else if (tokenAction.action == "delete")
          tokenAddresses = tokenAddresses.concat(await $c03143e0cae56add$export$1eb54f2f084fd3c6(this.transactionBuilder, this._availableAddresses, tokenAction.extraData.outpoint));
        else
          tokenAddresses = tokenAddresses.concat(await $c03143e0cae56add$export$49bc96b87058cba4(this.transactionBuilder, this._availableAddresses, tokenAction.token, tokenAction.amount, this.spentOutpoints));
        this._addressesToSignWith.concat(tokenAddresses);
      }
      nexaAddresses = nexaAddresses.concat(await $c03143e0cae56add$export$20e004915450ed44(this.transactionBuilder, this._availableAddresses, this.totalValue, this.txOptions, this.spentOutpoints));
      this._addressesToSignWith = tokenAddresses.concat(nexaAddresses);
    });
    return this;
  }
  /**
   * Parse transaction from buffer (not implemented for watch-only)
   * @param tx Transaction buffer
   * @returns This instance for chaining
   * @throws Error indicating method not implemented
   */
  parseTxBuffer(tx) {
    this.builder.push(async () => {
      this.transactionBuilder = new $bd99faf64de54a2c$export$2e2bcd8739ae039(tx);
    });
    return this;
  }
  /**
   * Parse transaction from hex string using enhanced base class implementation
   * @param tx Transaction hex string
   * @returns This instance for chaining
   */
  parseTxHex(tx) {
    return super.parseTxHex(tx);
  }
  /**
   * Handle watch-only specific logic for each parsed input (track addresses for signing)
   */
  async handleParsedInput(_input, utxo, _index) {
    if (utxo.addresses && utxo.addresses.length > 0) {
      const address = utxo.addresses[0];
      if (!this._addressesToSignWith.includes(address)) this._addressesToSignWith.push(address);
    }
  }
}
class $d3558bc9d24bb18b$export$2e2bcd8739ae039 {
  /**
   * Creates a new WatchOnlyWallet instance
   * @param addressesToWatch Array of addresses to monitor
   * @param network Optional network name (defaults to mainnet)
   * @throws Error if validation fails
   */
  constructor(addressesToWatch, network) {
    if (network !== void 0 && !isString(network)) throw new Error("Network must be a string");
    if (network !== void 0 && isString(network)) {
      const n = $149c1bd638913645$export$2e8191f482a38ccd.get(network);
      if (n === void 0) throw new Error(`Invalid network: ${network}`);
    }
    this._network = $149c1bd638913645$export$2e8191f482a38ccd.get(network) ?? $149c1bd638913645$export$2e8191f482a38ccd.mainnet;
    this._addressesToWatch = this.validateAddressesToWatch(addressesToWatch);
  }
  /**
   * Validates the addresses to watch array
   * @param addressesToWatch Array of addresses to validate
   * @returns Validated array of WatchOnlyAddress objects
   * @throws Error if validation fails
   */
  validateAddressesToWatch(addressesToWatch) {
    if (addressesToWatch === null || addressesToWatch === void 0) throw new Error("addresesToWatch is required");
    if (!isArray(addressesToWatch)) throw new Error("addressesToWatch must be an array");
    if (addressesToWatch.length === 0) throw new Error("addressesToWatch cannot be empty");
    const validatedAddresses = [];
    for (let i = 0; i < addressesToWatch.length; i++) {
      const addr = addressesToWatch[i];
      if (!isObject$1(addr) || isArray(addr)) throw new Error(`addressesToWatch[${i}] must be an object`);
      if (!addr.hasOwnProperty("address") || !isString(addr.address)) throw new Error(`addressesToWatch[${i}].address must be a string`);
      if (addr.address.trim() === "") throw new Error(`addressesToWatch[${i}].address cannot be empty`);
      if (!$6f559318d8845d29$export$8d986bd2866fe6ab(addr.address, this._network)) throw new Error(`addressesToWatch[${i}].address is not a valid NEXA address: ${addr.address}`);
      if (addr.xPub !== void 0 && !isObject$1(addr.xPub)) throw new Error(`addressesToWatch[${i}].xPub must be a PublicKey object`);
      if (addr.derivationPath !== void 0 && !isString(addr.derivationPath)) throw new Error(`addressesToWatch[${i}].derivationPath must be a string`);
      const isDuplicate = validatedAddresses.some((existingAddr) => existingAddr.address === addr.address);
      if (isDuplicate) throw new Error(`Duplicate address found: ${addr.address}`);
      validatedAddresses.push({
        address: addr.address.trim(),
        xPub: addr.xPub,
        derivationPath: addr.derivationPath
      });
    }
    return validatedAddresses;
  }
  /**
   * Creates a new transaction creator for this watch-only wallet
   * @param x Optional transaction data - can be a TransactionBuilder, hex string, or Buffer
   * @returns WatchOnlyTransactionCreator configured with wallet's addresses and network
   */
  newTransaction(x) {
    let tx;
    if (x instanceof $bd99faf64de54a2c$export$2e2bcd8739ae039)
      tx = new $fab743d51c8bbe7e$export$2e2bcd8739ae039(x);
    else if (isString(x))
      tx = new $fab743d51c8bbe7e$export$2e2bcd8739ae039().parseTxHex(x);
    else if (isBuffer(x) && !isNil(x))
      tx = new $fab743d51c8bbe7e$export$2e2bcd8739ae039().parseTxBuffer(x);
    else
      tx = new $fab743d51c8bbe7e$export$2e2bcd8739ae039();
    return tx.from(this._addressesToWatch).onNetwork(this._network);
  }
  /**
   * Broadcasts a signed transaction to the network
   * @param transaction Hex-encoded signed transaction
   * @returns Promise resolving to transaction ID
   * @throws Error if transaction is invalid or broadcast fails
   */
  async sendTransaction(transaction) {
    $006d7f03de390713$export$2e2bcd8739ae039.validateArgument(isString(transaction), "transaction must be present and valid");
    return $884ce55f1db7e177$export$eaa49f0478d81b9d.broadcast(transaction);
  }
  async subscribeToAddressNotifications(callback) {
    await $884ce55f1db7e177$export$eaa49f0478d81b9d.subscribeToAddresses(this._addressesToWatch.map((addr) => addr.address), callback);
  }
  /**
   * Unsubscribe from address notifications to prevent memory leaks
   * 
   * This method stops listening for notifications on all watched addresses.
   * The callback parameter must be the exact same function reference that was
   * used in the subscribeToAddressNotifications call.
   * 
   * @param callback - The exact same callback function used in subscribeToAddressNotifications
   * 
   * @example
   * ```typescript
   * const myCallback = (notification) => console.log(notification);
   * await watchOnlyWallet.subscribeToAddressNotifications(myCallback);
   * 
   * // Later, to prevent memory leaks:
   * await watchOnlyWallet.unsubscribeFromAddressNotifications(myCallback);
   * ```
   */
  async unsubscribeFromAddressNotifications(callback) {
    await $884ce55f1db7e177$export$eaa49f0478d81b9d.unsubscribeFromAddresses(this._addressesToWatch.map((addr) => addr.address), callback);
  }
  /**
   * Gets the list of addresses being watched
   * @returns Array of watched addresses (copy to prevent mutation)
   */
  getWatchedAddresses() {
    return [
      ...this._addressesToWatch
    ];
  }
}
const $5358ccf67a3d811b$export$618de809a659cb44 = {
  approveTransaction: async () => true,
  approveMessage: async () => true,
  approveSendTransaction: async () => true,
  approveNetworkSwitch: async () => true,
  approveAddToken: async () => true,
  approveConnection: async () => true
};
const $d838721b0af30ac5$var$getTokenOutputsFromTx = (txHex, network) => {
  const tokenOutputs = [];
  try {
    const transaction = new (0, $926e193f4c554367$export$2e2bcd8739ae039)(txHex);
    for (const output of transaction.outputs) if (output.type !== 0 && output.scriptPubKey.chunks[0]?.opcodenum >= 32) {
      const tokenIdHex = output.scriptPubKey.chunks[0].buf?.toString("hex");
      if (tokenIdHex && output.scriptPubKey.chunks[1]?.buf) {
        const tokenAddress = (0, $92cd415860c918d9$export$2e2bcd8739ae039).fromObject({
          data: tokenIdHex,
          network: network.toString(),
          type: (0, $c889a5b1bdeeb100$export$189c6ba3eaa96ac2).GroupIdAddress
        });
        if (tokenAddress !== null) {
          const tokenAddressStr = tokenAddress.toString();
          const tokenAmount = (0, $5aa97aebe18a7924$export$2e2bcd8739ae039).fromScriptNumBuffer(output.scriptPubKey.chunks[1].buf, false, 8).toBigInt();
          tokenOutputs.push({
            tokenId: tokenAddressStr,
            amount: tokenAmount.toString()
          });
        }
      }
    }
  } catch (error) {
    console.warn("Failed to extract token data from transaction:", error);
  }
  return tokenOutputs;
};
class $d838721b0af30ac5$export$11e896a2f3ae4119 {
  constructor(wallet, approvalCallbacks) {
    this.provider = null;
    this.currentAccount = null;
    this.isConnected = false;
    this.connectedDApp = null;
    this.wallet = wallet;
    this.approvalCallbacks = approvalCallbacks || $5358ccf67a3d811b$export$618de809a659cb44;
  }
  /**
   * Set approval callbacks for handling user consent
   */
  setApprovalCallbacks(callbacks) {
    this.approvalCallbacks = callbacks;
  }
  /**
   * Connect to a dApp using a pairing URI
   *
   * This method will only use DApp accounts for security isolation.
   * If no DApp account is provided, the first available one will be used or created.
   *
   * @param pairingURI - The pairing URI from the dApp (usually from QR code)
   * @param dappAccount - Optional specific DApp account to use (defaults to first available)
   * @returns Information about the connected dApp
   */
  async connect(pairingURI, dappAccount) {
    if (this.isConnected) this.disconnect();
    this.provider = new $fe6ed033804c8bce$export$2e2bcd8739ae039(pairingURI);
    this.setupHandlers();
    const dAppInfo = await this.provider.connect();
    if (this.approvalCallbacks.approveConnection) {
      const approved = await this.approvalCallbacks.approveConnection(dAppInfo);
      if (!approved) {
        this.provider.disconnect();
        throw new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.RequestRejected, "Connection rejected by user");
      }
    }
    this.connectedDApp = dAppInfo;
    if (dappAccount) {
      if (dappAccount.getAccountType() !== $6f559318d8845d29$export$b8ca5fa4899cbfc7.DAPP_ACCOUNT) throw new Error("Only DApp accounts can be used with WalletComms");
      this.currentAccount = dappAccount;
    } else this.currentAccount = await this.getOrCreateDAppAccount();
    const primaryAddress = this.currentAccount.getPrimaryAddressKey();
    await this.provider.joinSession(primaryAddress.address);
    this.isConnected = true;
    return dAppInfo;
  }
  /**
   * Get an existing DApp account or create a new one
   *
   * @returns A DApp account
   */
  async getOrCreateDAppAccount() {
    const dappAccounts = this.wallet.accountStore.getAccountsByType($6f559318d8845d29$export$b8ca5fa4899cbfc7.DAPP_ACCOUNT);
    if (dappAccounts.length > 0) return dappAccounts[0];
    return await this.wallet.newAccount($6f559318d8845d29$export$b8ca5fa4899cbfc7.DAPP_ACCOUNT);
  }
  /**
   * Disconnect from the current dApp session
   */
  disconnect() {
    if (this.provider) {
      this.provider.disconnect();
      this.provider = null;
    }
    this.isConnected = false;
    this.currentAccount = null;
  }
  /**
   * Set up handlers for dApp requests
   */
  setupHandlers() {
    if (!this.provider) return;
    this.provider.onSignMessage(async (request) => {
      try {
        const account = this.getAccountByAddress(request.account);
        if (!account) throw new (0, $abb7f0d6cff128a3$export$67bbc29c133d62a1)((0, $abb7f0d6cff128a3$export$4baa4fd50b453ebf).InvalidParams, `Account ${request.account} not found`);
        if (this.approvalCallbacks.approveMessage && this.connectedDApp) {
          const approvalDetails = {
            dApp: this.connectedDApp,
            account: request.account,
            message: request.message,
            messagePreview: request.message.length > 100 ? request.message.substring(0, 100) + "..." : request.message
          };
          const approved = await this.approvalCallbacks.approveMessage(approvalDetails);
          if (!approved) throw new (0, $abb7f0d6cff128a3$export$67bbc29c133d62a1)((0, $abb7f0d6cff128a3$export$4baa4fd50b453ebf).RequestRejected, "Message signing rejected by user");
        }
        return this.wallet.signMessage(request.message, request.account);
      } catch (error) {
        throw new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.InternalError, error instanceof Error ? error.message : "Failed to sign message");
      }
    });
    this.provider.on("wallet_getAccount", async () => {
      if (!this.currentAccount) throw new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.InternalError, "No account selected");
      const primaryAddress = this.currentAccount.getPrimaryAddressKey();
      return primaryAddress.address;
    });
    this.provider.on("wallet_getAccounts", async () => {
      const dappAccounts = this.wallet.accountStore.getAccountsByType($6f559318d8845d29$export$b8ca5fa4899cbfc7.DAPP_ACCOUNT);
      const addresses = [];
      for (const account of dappAccounts) {
        const primaryAddress = account.getPrimaryAddressKey();
        addresses.push(primaryAddress.address);
      }
      return addresses;
    });
    this.provider.on("wallet_signTransaction", async (request) => {
      try {
        const account = this.getAccountByAddress(request.account);
        if (!account) throw new (0, $abb7f0d6cff128a3$export$67bbc29c133d62a1)((0, $abb7f0d6cff128a3$export$4baa4fd50b453ebf).InvalidParams, `Account ${request.account} not found`);
        if (this.approvalCallbacks.approveTransaction && this.connectedDApp) {
          let totalAmount = "Unknown";
          let fees = "Unknown";
          try {
            const tempBuilder = this.wallet.newTransaction(account, request.hex);
            const tx2 = tempBuilder.transactionBuilder.build();
            let nexaTotal = 0n;
            for (const output of tx2.outputs) if (output.value != BigInt((0, $926e193f4c554367$export$2e2bcd8739ae039).DUST_AMOUNT)) nexaTotal += output.value;
            const estimatedFee = tx2.estimateRequiredFee();
            totalAmount = nexaTotal.toString();
            fees = estimatedFee.toString();
          } catch (error) {
            console.warn("Failed to parse transaction for approval details:", error);
          }
          const tokenOutputs = $d838721b0af30ac5$var$getTokenOutputsFromTx(request.hex, this.wallet.network);
          const approvalDetails = {
            dApp: this.connectedDApp,
            account: request.account,
            transactionHex: request.hex,
            broadcast: request.broadcast || false,
            totalAmount,
            fees,
            tokenOutputs: tokenOutputs.length > 0 ? tokenOutputs : void 0
          };
          const approved = await this.approvalCallbacks.approveTransaction(approvalDetails);
          if (!approved) throw new (0, $abb7f0d6cff128a3$export$67bbc29c133d62a1)((0, $abb7f0d6cff128a3$export$4baa4fd50b453ebf).RequestRejected, "Transaction signing rejected by user");
        }
        let txBuilder = this.wallet.newTransaction(account, request.hex);
        txBuilder = txBuilder.sign();
        const tx = await txBuilder.build();
        if (request.broadcast) return await this.wallet.sendTransaction(tx);
        return tx;
      } catch (error) {
        throw new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.InternalError, error instanceof Error ? error.message : "Failed to sign transaction");
      }
    });
    this.provider.on("wallet_sendTransaction", async (request) => {
      try {
        const account = this.getAccountByAddress(request.from);
        if (!account) throw new (0, $abb7f0d6cff128a3$export$67bbc29c133d62a1)((0, $abb7f0d6cff128a3$export$4baa4fd50b453ebf).InvalidParams, `Account ${request.from} not found`);
        let totalAmount = BigInt(0);
        for (const recipient of request.to) if (!recipient.token) totalAmount += BigInt(recipient.amount);
        if (this.approvalCallbacks.approveSendTransaction && this.connectedDApp) {
          const approvalDetails = {
            dApp: this.connectedDApp,
            fromAccount: request.from,
            recipients: request.to,
            totalAmount: totalAmount.toString(),
            opReturn: request.data
          };
          const approved = await this.approvalCallbacks.approveSendTransaction(approvalDetails);
          if (!approved) throw new (0, $abb7f0d6cff128a3$export$67bbc29c133d62a1)((0, $abb7f0d6cff128a3$export$4baa4fd50b453ebf).RequestRejected, "Send transaction rejected by user");
        }
        let txBuilder = this.wallet.newTransaction(account).onNetwork(this.wallet.network);
        for (const recipient of request.to) if (recipient.token) txBuilder = txBuilder.sendToToken(recipient.address, recipient.amount, recipient.token);
        else txBuilder = txBuilder.sendTo(recipient.address, recipient.amount);
        if (request.data) txBuilder = txBuilder.addOpReturn(request.data);
        const tx = await txBuilder.populate().sign().build();
        const txId = await this.wallet.sendTransaction(tx);
        return {
          txId,
          hex: tx
        };
      } catch (error) {
        throw new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.InternalError, error instanceof Error ? error.message : "Failed to send transaction");
      }
    });
    this.provider.on("wallet_switchNetwork", async (request) => {
      try {
        const network = (0, $149c1bd638913645$export$2e8191f482a38ccd).get(request.network);
        if (!network) throw new (0, $abb7f0d6cff128a3$export$67bbc29c133d62a1)((0, $abb7f0d6cff128a3$export$4baa4fd50b453ebf).InvalidParams, `Unknown network: ${request.network}`);
        await (0, $884ce55f1db7e177$export$eaa49f0478d81b9d).connect(request.network);
        return {
          success: true,
          network: request.network
        };
      } catch (error) {
        throw new $abb7f0d6cff128a3$export$67bbc29c133d62a1($abb7f0d6cff128a3$export$4baa4fd50b453ebf.InternalError, error instanceof Error ? error.message : "Failed to switch network");
      }
    });
    this.provider.on("wallet_addToken", async (request) => {
      console.log("Add token request:", request);
      return {
        success: true
      };
    });
    this.provider.onPeerDisconnect(() => {
      console.log("DApp disconnected");
      this.isConnected = false;
    });
    this.provider.onClose(() => {
      console.log("Connection closed");
      this.isConnected = false;
    });
  }
  /**
   * Get an account by its address
   */
  getAccountByAddress(address) {
    const accounts = this.wallet.accountStore.listAccounts();
    for (const [_, account] of accounts) {
      const addresses = account.getAddresses();
      if (addresses.some((addr) => addr.address === address)) return account;
    }
    return null;
  }
  /**
   * Switch the active account
   */
  setActiveAccount(account) {
    this.currentAccount = account;
  }
  /**
   * Get the current active account
   */
  getActiveAccount() {
    return this.currentAccount;
  }
  /**
   * Check if connected to a dApp
   */
  isConnectedToDApp() {
    return this.isConnected;
  }
  /**
   * Get the current session details
   */
  getSessionInfo() {
    if (!this.provider) return null;
    return this.provider.getSessionInfo();
  }
}
class $b55de282653776c6$export$80793d8292a1630a {
  /**
   * Creates a new DAppCommsProvider instance
   * @param relayUrl The WalletComms relay server URL
   * @param dAppInfo Information about your dApp
   * @param network Optional network (defaults to mainnet)
   */
  constructor(relayUrl, dAppInfo, network = "mainnet") {
    this.watchOnlyWallet = null;
    this.connectedWalletAddress = null;
    this.currentNetwork = "mainnet";
    this.provider = new $ff9d81fc068ff3b6$export$2e2bcd8739ae039(relayUrl, dAppInfo);
    this.currentNetwork = network;
  }
  /**
   * Connect to the WalletComms relay server
   * @returns Promise resolving when connected
   */
  async connect() {
    await this.provider.connect();
    await $884ce55f1db7e177$export$eaa49f0478d81b9d.connect(this.currentNetwork);
  }
  /**
   * Get the pairing URI for QR code display
   * @returns The pairing URI string
   */
  getPairingURI() {
    return this.provider.getPairingURI();
  }
  /**
   * Wait for a wallet to connect
   * @param timeout Timeout in milliseconds (default 30000)
   * @returns Promise resolving to the wallet address
   */
  async waitForWallet(timeout = 3e4) {
    try {
      const walletAddress = await this.provider.waitForWallet(timeout);
      this.connectedWalletAddress = walletAddress;
      this.watchOnlyWallet = new (0, $d3558bc9d24bb18b$export$2e2bcd8739ae039)([
        {
          address: walletAddress
        }
      ], this.currentNetwork);
      return walletAddress;
    } catch (error) {
      throw new Error(`Failed to connect wallet: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }
  /**
   * Send NEXA to an address
   * @param toAddress Destination address
   * @param amount Amount in satoshis (as string)
   * @param opReturnData Optional OP_RETURN data
   * @param broadcast Whether to broadcast immediately (default true)
   * @returns Promise resolving to transaction ID or signed hex
   */
  async sendTransaction(toAddress, amount, opReturnData, broadcast = true) {
    if (!this.watchOnlyWallet || !this.connectedWalletAddress) throw new Error("No wallet connected");
    let txBuilder = this.watchOnlyWallet.newTransaction().sendTo(toAddress, amount);
    if (opReturnData) txBuilder = txBuilder.addOpReturn(opReturnData);
    const unsignedTx = await txBuilder.populate().build();
    return await this.provider.signTransaction(this.connectedWalletAddress, unsignedTx, broadcast);
  }
  /**
   * Send tokens to an address
   * @param toAddress Destination address
   * @param amount Amount of tokens (as string)
   * @param tokenId Token ID
   * @param opReturnData Optional OP_RETURN data
   * @param broadcast Whether to broadcast immediately (default true)
   * @returns Promise resolving to transaction ID or signed hex
   */
  async sendTokenTransaction(toAddress, amount, tokenId, opReturnData, broadcast = true) {
    if (!this.watchOnlyWallet || !this.connectedWalletAddress) throw new Error("No wallet connected");
    let txBuilder = this.watchOnlyWallet.newTransaction().sendToToken(toAddress, amount, tokenId);
    if (opReturnData) txBuilder = txBuilder.addOpReturn(opReturnData);
    const unsignedTx = await txBuilder.populate().build();
    return await this.provider.signTransaction(this.connectedWalletAddress, unsignedTx, broadcast);
  }
  /**
   * Create and mint a new token
   * @param name Token name
   * @param ticker Token ticker symbol
   * @param decimals Number of decimal places
   * @param docUrl URL to token documentation
   * @param docHash Hash of token documentation
   * @param broadcast Whether to broadcast immediately (default true)
   * @returns Promise resolving to transaction ID or signed hex
   */
  async createToken(name, ticker, decimals, docUrl, docHash, broadcast = true) {
    if (!this.watchOnlyWallet || !this.connectedWalletAddress) throw new Error("No wallet connected");
    const unsignedTx = await this.watchOnlyWallet.newTransaction().token(name, ticker, decimals, docUrl, docHash).populate().build();
    return await this.provider.signTransaction(this.connectedWalletAddress, unsignedTx, broadcast);
  }
  /**
   * Create and mint a new NFT collection
   * @param name Collection name
   * @param ticker Collection ticker symbol
   * @param docUrl URL to collection documentation
   * @param docHash Hash of collection documentation
   * @param broadcast Whether to broadcast immediately (default true)
   * @returns Promise resolving to transaction ID or signed hex
   */
  async createCollection(name, ticker, docUrl, docHash, broadcast = true) {
    if (!this.watchOnlyWallet || !this.connectedWalletAddress) throw new Error("No wallet connected");
    const unsignedTx = await this.watchOnlyWallet.newTransaction().collection(name, ticker, docUrl, docHash).populate().build();
    return await this.provider.signTransaction(this.connectedWalletAddress, unsignedTx, broadcast);
  }
  /**
   * Create and mint an NFT within a collection
   * @param parentCollection Parent collection token ID
   * @param zipUrl URL to NFT content ZIP file
   * @param zipHash Hash of NFT content ZIP file
   * @param broadcast Whether to broadcast immediately (default true)
   * @returns Promise resolving to transaction ID or signed hex
   */
  async createNFT(parentCollection, zipUrl, zipHash, broadcast = true) {
    if (!this.watchOnlyWallet || !this.connectedWalletAddress) throw new Error("No wallet connected");
    const unsignedTx = await this.watchOnlyWallet.newTransaction().nft(parentCollection, zipUrl, zipHash).populate().build();
    return await this.provider.signTransaction(this.connectedWalletAddress, unsignedTx, broadcast);
  }
  /**
   * Create and mint an SFT (Semi-Fungible Token) within a collection with specified quantity
   * @param parentCollection Parent collection token ID
   * @param zipUrl URL to SFT content ZIP file
   * @param zipHash Hash of SFT content ZIP file
   * @param quantity Quantity of SFTs to create
   * @param broadcast Whether to broadcast immediately (default true)
   * @returns Promise resolving to transaction ID or signed hex
   */
  async createSFT(parentCollection, zipUrl, zipHash, quantity, broadcast = true) {
    if (!this.watchOnlyWallet || !this.connectedWalletAddress) throw new Error("No wallet connected");
    const unsignedTx = await this.watchOnlyWallet.newTransaction().sft(parentCollection, zipUrl, zipHash, quantity).populate().build();
    return await this.provider.signTransaction(this.connectedWalletAddress, unsignedTx, broadcast);
  }
  /**
   * Sign an arbitrary unsigned transaction
   * @param unsignedTx Unsigned transaction hex string
   * @param sighashSpec Optional sighash specification for selective signing
   * @param broadcast Whether to broadcast immediately (default false)
   * @returns Promise resolving to transaction ID (if broadcast) or signed hex
   */
  async signTransaction(unsignedTx, sighashSpec, broadcast = false) {
    if (!this.connectedWalletAddress) throw new Error("No wallet connected");
    return await this.provider.signTransaction(this.connectedWalletAddress, unsignedTx, broadcast);
  }
  /**
   * Build an unsigned transaction without signing
   * @param toAddress Destination address
   * @param amount Amount in satoshis (as string)
   * @param tokenId Optional token ID for token transfers
   * @param opReturnData Optional OP_RETURN data
   * @returns Promise resolving to unsigned transaction hex
   */
  async buildTransaction(toAddress, amount, tokenId, opReturnData) {
    if (!this.watchOnlyWallet) throw new Error("No wallet connected");
    let txBuilder = this.watchOnlyWallet.newTransaction();
    if (tokenId) txBuilder = txBuilder.sendToToken(toAddress, amount, tokenId);
    else txBuilder = txBuilder.sendTo(toAddress, amount);
    if (opReturnData) txBuilder = txBuilder.addOpReturn(opReturnData);
    return await txBuilder.populate().build();
  }
  /**
   * Build an unsigned token creation transaction
   * @param name Token name
   * @param ticker Token ticker symbol
   * @param decimals Number of decimal places
   * @param docUrl URL to token documentation
   * @param docHash Hash of token documentation
   * @returns Promise resolving to unsigned transaction hex
   */
  async buildTokenCreation(name, ticker, decimals, docUrl, docHash) {
    if (!this.watchOnlyWallet) throw new Error("No wallet connected");
    return await this.watchOnlyWallet.newTransaction().token(name, ticker, decimals, docUrl, docHash).populate().build();
  }
  /**
   * Build an unsigned collection creation transaction
   * @param name Collection name
   * @param ticker Collection ticker symbol
   * @param docUrl URL to collection documentation
   * @param docHash Hash of collection documentation
   * @returns Promise resolving to unsigned transaction hex
   */
  async buildCollectionCreation(name, ticker, docUrl, docHash) {
    if (!this.watchOnlyWallet) throw new Error("No wallet connected");
    return await this.watchOnlyWallet.newTransaction().collection(name, ticker, docUrl, docHash).populate().build();
  }
  /**
   * Build an unsigned NFT creation transaction
   * @param parentCollection Parent collection token ID
   * @param zipUrl URL to NFT content ZIP file
   * @param zipHash Hash of NFT content ZIP file
   * @returns Promise resolving to unsigned transaction hex
   */
  async buildNFTCreation(parentCollection, zipUrl, zipHash) {
    if (!this.watchOnlyWallet) throw new Error("No wallet connected");
    return await this.watchOnlyWallet.newTransaction().nft(parentCollection, zipUrl, zipHash).populate().build();
  }
  /**
   * Build an unsigned SFT creation transaction
   * @param parentCollection Parent collection token ID
   * @param zipUrl URL to SFT content ZIP file
   * @param zipHash Hash of SFT content ZIP file
   * @param quantity Quantity of SFTs to create
   * @returns Promise resolving to unsigned transaction hex
   */
  async buildSFTCreation(parentCollection, zipUrl, zipHash, quantity) {
    if (!this.watchOnlyWallet) throw new Error("No wallet connected");
    return await this.watchOnlyWallet.newTransaction().sft(parentCollection, zipUrl, zipHash, quantity).populate().build();
  }
  /**
   * Initialize WatchOnlyWallet with multiple addresses
   * @param addresses Array of addresses to watch
   */
  initializeWatchOnly(addresses) {
    this.watchOnlyWallet = new $d3558bc9d24bb18b$export$2e2bcd8739ae039(addresses.map((addr) => ({
      address: addr
    })), this.currentNetwork);
  }
  /**
   * Create a custom unsigned transaction
   * @param txBuilder Function that configures the transaction builder
   * @param sighashSpec Optional sighash specification for selective signing
   * @param broadcast Whether to broadcast immediately (default true)
   * @returns Promise resolving to transaction ID or signed hex
   */
  async createCustomTransaction(txBuilder, sighashSpec, broadcast = true) {
    if (!this.watchOnlyWallet || !this.connectedWalletAddress) throw new Error("No wallet connected");
    const builder = this.watchOnlyWallet.newTransaction();
    const configuredBuilder = txBuilder(builder);
    const unsignedTx = await configuredBuilder.populate().build();
    return await this.provider.signTransaction(this.connectedWalletAddress, unsignedTx, broadcast);
  }
  /**
   * Sign a message with the connected wallet
   * @param message Message to sign
   * @returns Promise resolving to the signature
   */
  async signMessage(message) {
    if (!this.connectedWalletAddress) throw new Error("No wallet connected");
    return await this.provider.signMessage(this.connectedWalletAddress, message);
  }
  /**
   * Switch to a different network
   * @param network Network name or identifier
   * @returns Promise resolving when network is switched
   */
  async switchNetwork(network) {
    await this.provider.switchNetwork(network);
    this.currentNetwork = network;
    await $884ce55f1db7e177$export$eaa49f0478d81b9d.connect(network);
    if (this.watchOnlyWallet && this.connectedWalletAddress) this.watchOnlyWallet = new $d3558bc9d24bb18b$export$2e2bcd8739ae039([
      {
        address: this.connectedWalletAddress
      }
    ], network);
  }
  /**
   * Get the currently connected wallet address
   * @returns Wallet address or null if not connected
   */
  getConnectedWallet() {
    return this.connectedWalletAddress;
  }
  /**
   * Check if a wallet is currently connected
   * @returns True if wallet is connected
   */
  isConnected() {
    return this.connectedWalletAddress !== null;
  }
  /**
   * Get the current network
   * @returns Current network identifier
   */
  getCurrentNetwork() {
    return this.currentNetwork;
  }
  /**
   * Get the underlying WatchOnlyWallet instance
   * @returns WatchOnlyWallet instance or null if not connected
   */
  getWatchOnlyWallet() {
    return this.watchOnlyWallet;
  }
  /**
   * Disconnect from the wallet
   */
  disconnect() {
    this.provider.disconnect();
    this.watchOnlyWallet = null;
    this.connectedWalletAddress = null;
  }
  /**
   * Set up event listeners for wallet events
   * @param event Event name
   * @param callback Event callback
   */
  on(event, callback) {
    this.provider.on(event, callback);
  }
  /**
   * Remove event listeners
   * @param event Event name
   */
  off(event) {
    this.provider.off(event);
  }
  /**
   * Set up wallet disconnect event listener
   * @param callback Function to call when wallet disconnects
   */
  onWalletDisconnect(callback) {
    this.provider.onPeerDisconnect(() => {
      this.watchOnlyWallet = null;
      this.connectedWalletAddress = null;
      callback();
    });
  }
  /**
   * Set up connection close event listener
   * @param callback Function to call when connection closes
   */
  onConnectionClose(callback) {
    this.provider.onClose(() => {
      this.watchOnlyWallet = null;
      this.connectedWalletAddress = null;
      callback();
    });
  }
}
function $149c1bd638913645$var$versionGuard(version) {
  if (version !== void 0) {
    let message = "More than one instance of Wallet SDKPlease make sure to require Wallet SDK and check that submodules do not also include their own Wallet SDK dependency.";
    throw new Error(message);
  }
}
$149c1bd638913645$var$versionGuard($parcel$global._walletSdk_ver);
$parcel$global._walletSdk_ver = `v${$df64573ef6d51081$exports.version}`;
const $149c1bd638913645$var$walletSdk = {
  versionGuard: $149c1bd638913645$var$versionGuard,
  version: `v${$df64573ef6d51081$exports.version}`,
  Wallet: $8265cc68049fe82c$export$2e2bcd8739ae039
};
var $149c1bd638913645$export$2e2bcd8739ae039 = $149c1bd638913645$var$walletSdk;
export {
  $5358ccf67a3d811b$export$618de809a659cb44 as AUTO_APPROVE_CALLBACKS,
  $441c371114e3ba96$export$94f569bf4eb0f6f6 as AccountKeysUtils,
  $7e26340ce0f64954$export$2e2bcd8739ae039 as AccountStore,
  $6f559318d8845d29$export$b8ca5fa4899cbfc7 as AccountType,
  $b76a3f2ef1862027$export$c54c8796e94a37a0 as BaseAccount,
  $b55de282653776c6$export$80793d8292a1630a as DAppCommsProvider,
  $448355556707518b$export$2e2bcd8739ae039 as DappAccount,
  $5c605efdbcfd6698$export$2e2bcd8739ae039 as DefaultAccount,
  $e50a883097cd2090$export$2e2bcd8739ae039 as SighashType,
  $6f559318d8845d29$export$dcc1fb6ad5308e56 as TxTokenType,
  $006d7f03de390713$export$2e2bcd8739ae039 as ValidationUtils,
  $ce8955c0465759ad$export$2e2bcd8739ae039 as VaultAccount,
  $8265cc68049fe82c$export$2e2bcd8739ae039 as Wallet,
  $d838721b0af30ac5$export$11e896a2f3ae4119 as WalletCommsIntegration,
  $d71d9063d6876a10$export$2e2bcd8739ae039 as WalletTransactionCreator,
  $fab743d51c8bbe7e$export$2e2bcd8739ae039 as WatchOnlyTransactionCreator,
  $d3558bc9d24bb18b$export$2e2bcd8739ae039 as WatchOnlyWallet,
  $149c1bd638913645$export$2e2bcd8739ae039 as default,
  $6f559318d8845d29$export$8d986bd2866fe6ab as isValidNexaAddress,
  $884ce55f1db7e177$export$eaa49f0478d81b9d as rostrumProvider
};
//# sourceMappingURL=index.web-BXlmGF_y.js.map
