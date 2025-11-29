const Yt = {}, nu = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  default: Yt
}, Symbol.toStringTag, { value: "Module" }));
var us = typeof globalThis == "object" && globalThis && globalThis.Object === Object && globalThis, ou = typeof self == "object" && self && self.Object === Object && self, ir = us || ou || Function("return this")(), Zr = ir.Symbol, fs = Object.prototype, su = fs.hasOwnProperty, uu = fs.toString, ti = Zr ? Zr.toStringTag : void 0;
function fu(r) {
  var e = su.call(r, ti), t = r[ti];
  try {
    r[ti] = void 0;
    var i = !0;
  } catch {
  }
  var o = uu.call(r);
  return i && (e ? r[ti] = t : delete r[ti]), o;
}
var cu = Object.prototype, lu = cu.toString;
function hu(r) {
  return lu.call(r);
}
var du = "[object Null]", pu = "[object Undefined]", Mn = Zr ? Zr.toStringTag : void 0;
function ar(r) {
  return r == null ? r === void 0 ? pu : du : Mn && Mn in Object(r) ? fu(r) : hu(r);
}
function Ur(r) {
  return r != null && typeof r == "object";
}
var mu = "[object Symbol]";
function cs(r) {
  return typeof r == "symbol" || Ur(r) && ar(r) == mu;
}
function bu(r, e) {
  for (var t = -1, i = r == null ? 0 : r.length, o = Array(i); ++t < i; )
    o[t] = e(r[t], t, r);
  return o;
}
var rr = Array.isArray, Bn = Zr ? Zr.prototype : void 0, In = Bn ? Bn.toString : void 0;
function ls(r) {
  if (typeof r == "string")
    return r;
  if (rr(r))
    return bu(r, ls) + "";
  if (cs(r))
    return In ? In.call(r) : "";
  var e = r + "";
  return e == "0" && 1 / r == -1 / 0 ? "-0" : e;
}
var vu = /\s/;
function gu(r) {
  for (var e = r.length; e-- && vu.test(r.charAt(e)); )
    ;
  return e;
}
var yu = /^\s+/;
function wu(r) {
  return r && r.slice(0, gu(r) + 1).replace(yu, "");
}
function Oe(r) {
  var e = typeof r;
  return r != null && (e == "object" || e == "function");
}
var En = NaN, xu = /^[-+]0x[0-9a-f]+$/i, ku = /^0b[01]+$/i, Su = /^0o[0-7]+$/i, Au = parseInt;
function hs(r) {
  if (typeof r == "number")
    return r;
  if (cs(r))
    return En;
  if (Oe(r)) {
    var e = typeof r.valueOf == "function" ? r.valueOf() : r;
    r = Oe(e) ? e + "" : e;
  }
  if (typeof r != "string")
    return r === 0 ? r : +r;
  r = wu(r);
  var t = ku.test(r);
  return t || Su.test(r) ? Au(r.slice(2), t ? 2 : 8) : xu.test(r) ? En : +r;
}
var Pn = 1 / 0, _u = 17976931348623157e292;
function Ta(r) {
  if (!r)
    return r === 0 ? r : 0;
  if (r = hs(r), r === Pn || r === -Pn) {
    var e = r < 0 ? -1 : 1;
    return e * _u;
  }
  return r === r ? r : 0;
}
function Mu(r) {
  var e = Ta(r), t = e % 1;
  return e === e ? t ? e - t : e : 0;
}
var Bu = "[object AsyncFunction]", Iu = "[object Function]", Eu = "[object GeneratorFunction]", Pu = "[object Proxy]";
function ds(r) {
  if (!Oe(r))
    return !1;
  var e = ar(r);
  return e == Iu || e == Eu || e == Bu || e == Pu;
}
var Vi = ir["__core-js_shared__"], Tn = (function() {
  var r = /[^.]+$/.exec(Vi && Vi.keys && Vi.keys.IE_PROTO || "");
  return r ? "Symbol(src)_1." + r : "";
})();
function Tu(r) {
  return !!Tn && Tn in r;
}
var zu = Function.prototype, Ou = zu.toString;
function jr(r) {
  if (r != null) {
    try {
      return Ou.call(r);
    } catch {
    }
    try {
      return r + "";
    } catch {
    }
  }
  return "";
}
var Nu = /[\\^$.*+?()[\]{}|]/g, Cu = /^\[object .+?Constructor\]$/, Fu = Function.prototype, Ru = Object.prototype, Lu = Fu.toString, Uu = Ru.hasOwnProperty, ju = RegExp(
  "^" + Lu.call(Uu).replace(Nu, "\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$"
);
function Ku(r) {
  if (!Oe(r) || Tu(r))
    return !1;
  var e = ds(r) ? ju : Cu;
  return e.test(jr(r));
}
function qu(r, e) {
  return r?.[e];
}
function ui(r, e) {
  var t = qu(r, e);
  return Ku(t) ? t : void 0;
}
var za = ui(ir, "WeakMap"), Du = 9007199254740991;
function ps(r) {
  return typeof r == "number" && r > -1 && r % 1 == 0 && r <= Du;
}
function Hu(r) {
  return r != null && ps(r.length) && !ds(r);
}
var Vu = Object.prototype;
function ms(r) {
  var e = r && r.constructor, t = typeof e == "function" && e.prototype || Vu;
  return r === t;
}
var Gu = "[object Arguments]";
function zn(r) {
  return Ur(r) && ar(r) == Gu;
}
var bs = Object.prototype, Wu = bs.hasOwnProperty, Ju = bs.propertyIsEnumerable, Yu = zn(/* @__PURE__ */ (function() {
  return arguments;
})()) ? zn : function(r) {
  return Ur(r) && Wu.call(r, "callee") && !Ju.call(r, "callee");
};
function Xu() {
  return !1;
}
var vs = typeof exports == "object" && exports && !exports.nodeType && exports, On = vs && typeof module == "object" && module && !module.nodeType && module, Zu = On && On.exports === vs, Nn = Zu ? ir.Buffer : void 0, Qu = Nn ? Nn.isBuffer : void 0, gs = Qu || Xu, $u = "[object Arguments]", ef = "[object Array]", tf = "[object Boolean]", rf = "[object Date]", af = "[object Error]", nf = "[object Function]", of = "[object Map]", sf = "[object Number]", uf = "[object Object]", ff = "[object RegExp]", cf = "[object Set]", lf = "[object String]", hf = "[object WeakMap]", df = "[object ArrayBuffer]", pf = "[object DataView]", mf = "[object Float32Array]", bf = "[object Float64Array]", vf = "[object Int8Array]", gf = "[object Int16Array]", yf = "[object Int32Array]", wf = "[object Uint8Array]", xf = "[object Uint8ClampedArray]", kf = "[object Uint16Array]", Sf = "[object Uint32Array]", Xe = {};
Xe[mf] = Xe[bf] = Xe[vf] = Xe[gf] = Xe[yf] = Xe[wf] = Xe[xf] = Xe[kf] = Xe[Sf] = !0;
Xe[$u] = Xe[ef] = Xe[df] = Xe[tf] = Xe[pf] = Xe[rf] = Xe[af] = Xe[nf] = Xe[of] = Xe[sf] = Xe[uf] = Xe[ff] = Xe[cf] = Xe[lf] = Xe[hf] = !1;
function Af(r) {
  return Ur(r) && ps(r.length) && !!Xe[ar(r)];
}
function ys(r) {
  return function(e) {
    return r(e);
  };
}
var ws = typeof exports == "object" && exports && !exports.nodeType && exports, ai = ws && typeof module == "object" && module && !module.nodeType && module, _f = ai && ai.exports === ws, Gi = _f && us.process, Pi = (function() {
  try {
    var r = ai && ai.require && ai.require("util").types;
    return r || Gi && Gi.binding && Gi.binding("util");
  } catch {
  }
})(), Cn = Pi && Pi.isTypedArray, Mf = Cn ? ys(Cn) : Af;
function Bf(r, e) {
  return function(t) {
    return r(e(t));
  };
}
var If = Bf(Object.keys, Object), Ef = Object.prototype, Pf = Ef.hasOwnProperty;
function Tf(r) {
  if (!ms(r))
    return If(r);
  var e = [];
  for (var t in Object(r))
    Pf.call(r, t) && t != "constructor" && e.push(t);
  return e;
}
var Oa = ui(ir, "Map");
function zf(r) {
  return r == null ? "" : ls(r);
}
var Na = ui(ir, "DataView"), Ca = ui(ir, "Promise"), Fa = ui(ir, "Set"), Fn = "[object Map]", Of = "[object Object]", Rn = "[object Promise]", Ln = "[object Set]", Un = "[object WeakMap]", jn = "[object DataView]", Nf = jr(Na), Cf = jr(Oa), Ff = jr(Ca), Rf = jr(Fa), Lf = jr(za), Fr = ar;
(Na && Fr(new Na(new ArrayBuffer(1))) != jn || Oa && Fr(new Oa()) != Fn || Ca && Fr(Ca.resolve()) != Rn || Fa && Fr(new Fa()) != Ln || za && Fr(new za()) != Un) && (Fr = function(r) {
  var e = ar(r), t = e == Of ? r.constructor : void 0, i = t ? jr(t) : "";
  if (i)
    switch (i) {
      case Nf:
        return jn;
      case Cf:
        return Fn;
      case Ff:
        return Rn;
      case Rf:
        return Ln;
      case Lf:
        return Un;
    }
  return e;
});
var Uf = Math.max, jf = Math.min;
function Kf(r, e, t) {
  return r >= jf(e, t) && r < Uf(e, t);
}
function lr(r, e, t) {
  return e = Ta(e), t === void 0 ? (t = e, e = 0) : t = Ta(t), r = hs(r), Kf(r, e, t);
}
var qf = "[object String]";
function te(r) {
  return typeof r == "string" || !rr(r) && Ur(r) && ar(r) == qf;
}
var Df = "[object Date]";
function Hf(r) {
  return Ur(r) && ar(r) == Df;
}
var Kn = Pi && Pi.isDate, Vf = Kn ? ys(Kn) : Hf, Gf = "[object Map]", Wf = "[object Set]", Jf = Object.prototype, Yf = Jf.hasOwnProperty;
function Kt(r) {
  if (r == null)
    return !0;
  if (Hu(r) && (rr(r) || typeof r == "string" || typeof r.splice == "function" || gs(r) || Mf(r) || Yu(r)))
    return !r.length;
  var e = Fr(r);
  if (e == Gf || e == Wf)
    return !r.size;
  if (ms(r))
    return !Tf(r).length;
  for (var t in r)
    if (Yf.call(r, t))
      return !1;
  return !0;
}
function qn(r) {
  return typeof r == "number" && r == Mu(r);
}
var Xf = "[object Number]";
function Tt(r) {
  return typeof r == "number" || Ur(r) && ar(r) == Xf;
}
function ze(r) {
  return r == null;
}
function Zf(r) {
  return r === null;
}
function oe(r) {
  return r === void 0;
}
var Qf = /^\s+/, $f = ir.parseInt;
function Dn(r, e, t) {
  return t || e == null ? e = 0 : e && (e = +e), $f(zf(r).replace(Qf, ""), e || 0);
}
function Fi(r) {
  return r && r.__esModule && Object.prototype.hasOwnProperty.call(r, "default") ? r.default : r;
}
function fi(r) {
  if (Object.prototype.hasOwnProperty.call(r, "__esModule")) return r;
  var e = r.default;
  if (typeof e == "function") {
    var t = function i() {
      return this instanceof i ? Reflect.construct(e, arguments, this.constructor) : e.apply(this, arguments);
    };
    t.prototype = e.prototype;
  } else t = {};
  return Object.defineProperty(t, "__esModule", { value: !0 }), Object.keys(r).forEach(function(i) {
    var o = Object.getOwnPropertyDescriptor(r, i);
    Object.defineProperty(t, i, o.get ? o : {
      enumerable: !0,
      get: function() {
        return r[i];
      }
    });
  }), t;
}
var Mi = { exports: {} };
const an = /* @__PURE__ */ fi(nu);
var ec = Mi.exports, Hn;
function tc() {
  return Hn || (Hn = 1, (function(r) {
    (function(e, t) {
      function i(u, n) {
        if (!u) throw new Error(n || "Assertion failed");
      }
      function o(u, n) {
        u.super_ = n;
        var s = function() {
        };
        s.prototype = n.prototype, u.prototype = new s(), u.prototype.constructor = u;
      }
      function a(u, n, s) {
        if (a.isBN(u))
          return u;
        this.negative = 0, this.words = null, this.length = 0, this.red = null, u !== null && ((n === "le" || n === "be") && (s = n, n = 10), this._init(u || 0, n || 10, s || "be"));
      }
      typeof e == "object" ? e.exports = a : t.BN = a, a.BN = a, a.wordSize = 26;
      var p;
      try {
        typeof window < "u" && typeof window.Buffer < "u" ? p = window.Buffer : p = an.Buffer;
      } catch {
      }
      a.isBN = function(n) {
        return n instanceof a ? !0 : n !== null && typeof n == "object" && n.constructor.wordSize === a.wordSize && Array.isArray(n.words);
      }, a.max = function(n, s) {
        return n.cmp(s) > 0 ? n : s;
      }, a.min = function(n, s) {
        return n.cmp(s) < 0 ? n : s;
      }, a.prototype._init = function(n, s, d) {
        if (typeof n == "number")
          return this._initNumber(n, s, d);
        if (typeof n == "object")
          return this._initArray(n, s, d);
        s === "hex" && (s = 16), i(s === (s | 0) && s >= 2 && s <= 36), n = n.toString().replace(/\s+/g, "");
        var w = 0;
        n[0] === "-" && (w++, this.negative = 1), w < n.length && (s === 16 ? this._parseHex(n, w, d) : (this._parseBase(n, s, w), d === "le" && this._initArray(this.toArray(), s, d)));
      }, a.prototype._initNumber = function(n, s, d) {
        n < 0 && (this.negative = 1, n = -n), n < 67108864 ? (this.words = [n & 67108863], this.length = 1) : n < 4503599627370496 ? (this.words = [
          n & 67108863,
          n / 67108864 & 67108863
        ], this.length = 2) : (i(n < 9007199254740992), this.words = [
          n & 67108863,
          n / 67108864 & 67108863,
          1
        ], this.length = 3), d === "le" && this._initArray(this.toArray(), s, d);
      }, a.prototype._initArray = function(n, s, d) {
        if (i(typeof n.length == "number"), n.length <= 0)
          return this.words = [0], this.length = 1, this;
        this.length = Math.ceil(n.length / 3), this.words = new Array(this.length);
        for (var w = 0; w < this.length; w++)
          this.words[w] = 0;
        var A, k, l = 0;
        if (d === "be")
          for (w = n.length - 1, A = 0; w >= 0; w -= 3)
            k = n[w] | n[w - 1] << 8 | n[w - 2] << 16, this.words[A] |= k << l & 67108863, this.words[A + 1] = k >>> 26 - l & 67108863, l += 24, l >= 26 && (l -= 26, A++);
        else if (d === "le")
          for (w = 0, A = 0; w < n.length; w += 3)
            k = n[w] | n[w + 1] << 8 | n[w + 2] << 16, this.words[A] |= k << l & 67108863, this.words[A + 1] = k >>> 26 - l & 67108863, l += 24, l >= 26 && (l -= 26, A++);
        return this._strip();
      };
      function c(u, n) {
        var s = u.charCodeAt(n);
        if (s >= 48 && s <= 57)
          return s - 48;
        if (s >= 65 && s <= 70)
          return s - 55;
        if (s >= 97 && s <= 102)
          return s - 87;
        i(!1, "Invalid character in " + u);
      }
      function g(u, n, s) {
        var d = c(u, s);
        return s - 1 >= n && (d |= c(u, s - 1) << 4), d;
      }
      a.prototype._parseHex = function(n, s, d) {
        this.length = Math.ceil((n.length - s) / 6), this.words = new Array(this.length);
        for (var w = 0; w < this.length; w++)
          this.words[w] = 0;
        var A = 0, k = 0, l;
        if (d === "be")
          for (w = n.length - 1; w >= s; w -= 2)
            l = g(n, s, w) << A, this.words[k] |= l & 67108863, A >= 18 ? (A -= 18, k += 1, this.words[k] |= l >>> 26) : A += 8;
        else {
          var y = n.length - s;
          for (w = y % 2 === 0 ? s + 1 : s; w < n.length; w += 2)
            l = g(n, s, w) << A, this.words[k] |= l & 67108863, A >= 18 ? (A -= 18, k += 1, this.words[k] |= l >>> 26) : A += 8;
        }
        this._strip();
      };
      function h(u, n, s, d) {
        for (var w = 0, A = 0, k = Math.min(u.length, s), l = n; l < k; l++) {
          var y = u.charCodeAt(l) - 48;
          w *= d, y >= 49 ? A = y - 49 + 10 : y >= 17 ? A = y - 17 + 10 : A = y, i(y >= 0 && A < d, "Invalid character"), w += A;
        }
        return w;
      }
      a.prototype._parseBase = function(n, s, d) {
        this.words = [0], this.length = 1;
        for (var w = 0, A = 1; A <= 67108863; A *= s)
          w++;
        w--, A = A / s | 0;
        for (var k = n.length - d, l = k % w, y = Math.min(k, k - l) + d, v = 0, P = d; P < y; P += w)
          v = h(n, P, P + w, s), this.imuln(A), this.words[0] + v < 67108864 ? this.words[0] += v : this._iaddn(v);
        if (l !== 0) {
          var J = 1;
          for (v = h(n, P, n.length, s), P = 0; P < l; P++)
            J *= s;
          this.imuln(J), this.words[0] + v < 67108864 ? this.words[0] += v : this._iaddn(v);
        }
        this._strip();
      }, a.prototype.copy = function(n) {
        n.words = new Array(this.length);
        for (var s = 0; s < this.length; s++)
          n.words[s] = this.words[s];
        n.length = this.length, n.negative = this.negative, n.red = this.red;
      };
      function m(u, n) {
        u.words = n.words, u.length = n.length, u.negative = n.negative, u.red = n.red;
      }
      if (a.prototype._move = function(n) {
        m(n, this);
      }, a.prototype.clone = function() {
        var n = new a(null);
        return this.copy(n), n;
      }, a.prototype._expand = function(n) {
        for (; this.length < n; )
          this.words[this.length++] = 0;
        return this;
      }, a.prototype._strip = function() {
        for (; this.length > 1 && this.words[this.length - 1] === 0; )
          this.length--;
        return this._normSign();
      }, a.prototype._normSign = function() {
        return this.length === 1 && this.words[0] === 0 && (this.negative = 0), this;
      }, typeof Symbol < "u" && typeof Symbol.for == "function")
        try {
          a.prototype[Symbol.for("nodejs.util.inspect.custom")] = S;
        } catch {
          a.prototype.inspect = S;
        }
      else
        a.prototype.inspect = S;
      function S() {
        return (this.red ? "<BN-R: " : "<BN: ") + this.toString(16) + ">";
      }
      var M = [
        "",
        "0",
        "00",
        "000",
        "0000",
        "00000",
        "000000",
        "0000000",
        "00000000",
        "000000000",
        "0000000000",
        "00000000000",
        "000000000000",
        "0000000000000",
        "00000000000000",
        "000000000000000",
        "0000000000000000",
        "00000000000000000",
        "000000000000000000",
        "0000000000000000000",
        "00000000000000000000",
        "000000000000000000000",
        "0000000000000000000000",
        "00000000000000000000000",
        "000000000000000000000000",
        "0000000000000000000000000"
      ], I = [
        0,
        0,
        25,
        16,
        12,
        11,
        10,
        9,
        8,
        8,
        7,
        7,
        7,
        7,
        6,
        6,
        6,
        6,
        6,
        6,
        6,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5
      ], _ = [
        0,
        0,
        33554432,
        43046721,
        16777216,
        48828125,
        60466176,
        40353607,
        16777216,
        43046721,
        1e7,
        19487171,
        35831808,
        62748517,
        7529536,
        11390625,
        16777216,
        24137569,
        34012224,
        47045881,
        64e6,
        4084101,
        5153632,
        6436343,
        7962624,
        9765625,
        11881376,
        14348907,
        17210368,
        20511149,
        243e5,
        28629151,
        33554432,
        39135393,
        45435424,
        52521875,
        60466176
      ];
      a.prototype.toString = function(n, s) {
        n = n || 10, s = s | 0 || 1;
        var d;
        if (n === 16 || n === "hex") {
          d = "";
          for (var w = 0, A = 0, k = 0; k < this.length; k++) {
            var l = this.words[k], y = ((l << w | A) & 16777215).toString(16);
            A = l >>> 24 - w & 16777215, w += 2, w >= 26 && (w -= 26, k--), A !== 0 || k !== this.length - 1 ? d = M[6 - y.length] + y + d : d = y + d;
          }
          for (A !== 0 && (d = A.toString(16) + d); d.length % s !== 0; )
            d = "0" + d;
          return this.negative !== 0 && (d = "-" + d), d;
        }
        if (n === (n | 0) && n >= 2 && n <= 36) {
          var v = I[n], P = _[n];
          d = "";
          var J = this.clone();
          for (J.negative = 0; !J.isZero(); ) {
            var Y = J.modrn(P).toString(n);
            J = J.idivn(P), J.isZero() ? d = Y + d : d = M[v - Y.length] + Y + d;
          }
          for (this.isZero() && (d = "0" + d); d.length % s !== 0; )
            d = "0" + d;
          return this.negative !== 0 && (d = "-" + d), d;
        }
        i(!1, "Base should be between 2 and 36");
      }, a.prototype.toNumber = function() {
        var n = this.words[0];
        return this.length === 2 ? n += this.words[1] * 67108864 : this.length === 3 && this.words[2] === 1 ? n += 4503599627370496 + this.words[1] * 67108864 : this.length > 2 && i(!1, "Number can only safely store up to 53 bits"), this.negative !== 0 ? -n : n;
      }, a.prototype.toJSON = function() {
        return this.toString(16, 2);
      }, p && (a.prototype.toBuffer = function(n, s) {
        return this.toArrayLike(p, n, s);
      }), a.prototype.toArray = function(n, s) {
        return this.toArrayLike(Array, n, s);
      };
      var E = function(n, s) {
        return n.allocUnsafe ? n.allocUnsafe(s) : new n(s);
      };
      a.prototype.toArrayLike = function(n, s, d) {
        this._strip();
        var w = this.byteLength(), A = d || Math.max(1, w);
        i(w <= A, "byte array longer than desired length"), i(A > 0, "Requested array length <= 0");
        var k = E(n, A), l = s === "le" ? "LE" : "BE";
        return this["_toArrayLike" + l](k, w), k;
      }, a.prototype._toArrayLikeLE = function(n, s) {
        for (var d = 0, w = 0, A = 0, k = 0; A < this.length; A++) {
          var l = this.words[A] << k | w;
          n[d++] = l & 255, d < n.length && (n[d++] = l >> 8 & 255), d < n.length && (n[d++] = l >> 16 & 255), k === 6 ? (d < n.length && (n[d++] = l >> 24 & 255), w = 0, k = 0) : (w = l >>> 24, k += 2);
        }
        if (d < n.length)
          for (n[d++] = w; d < n.length; )
            n[d++] = 0;
      }, a.prototype._toArrayLikeBE = function(n, s) {
        for (var d = n.length - 1, w = 0, A = 0, k = 0; A < this.length; A++) {
          var l = this.words[A] << k | w;
          n[d--] = l & 255, d >= 0 && (n[d--] = l >> 8 & 255), d >= 0 && (n[d--] = l >> 16 & 255), k === 6 ? (d >= 0 && (n[d--] = l >> 24 & 255), w = 0, k = 0) : (w = l >>> 24, k += 2);
        }
        if (d >= 0)
          for (n[d--] = w; d >= 0; )
            n[d--] = 0;
      }, Math.clz32 ? a.prototype._countBits = function(n) {
        return 32 - Math.clz32(n);
      } : a.prototype._countBits = function(n) {
        var s = n, d = 0;
        return s >= 4096 && (d += 13, s >>>= 13), s >= 64 && (d += 7, s >>>= 7), s >= 8 && (d += 4, s >>>= 4), s >= 2 && (d += 2, s >>>= 2), d + s;
      }, a.prototype._zeroBits = function(n) {
        if (n === 0) return 26;
        var s = n, d = 0;
        return (s & 8191) === 0 && (d += 13, s >>>= 13), (s & 127) === 0 && (d += 7, s >>>= 7), (s & 15) === 0 && (d += 4, s >>>= 4), (s & 3) === 0 && (d += 2, s >>>= 2), (s & 1) === 0 && d++, d;
      }, a.prototype.bitLength = function() {
        var n = this.words[this.length - 1], s = this._countBits(n);
        return (this.length - 1) * 26 + s;
      };
      function O(u) {
        for (var n = new Array(u.bitLength()), s = 0; s < n.length; s++) {
          var d = s / 26 | 0, w = s % 26;
          n[s] = u.words[d] >>> w & 1;
        }
        return n;
      }
      a.prototype.zeroBits = function() {
        if (this.isZero()) return 0;
        for (var n = 0, s = 0; s < this.length; s++) {
          var d = this._zeroBits(this.words[s]);
          if (n += d, d !== 26) break;
        }
        return n;
      }, a.prototype.byteLength = function() {
        return Math.ceil(this.bitLength() / 8);
      }, a.prototype.toTwos = function(n) {
        return this.negative !== 0 ? this.abs().inotn(n).iaddn(1) : this.clone();
      }, a.prototype.fromTwos = function(n) {
        return this.testn(n - 1) ? this.notn(n).iaddn(1).ineg() : this.clone();
      }, a.prototype.isNeg = function() {
        return this.negative !== 0;
      }, a.prototype.neg = function() {
        return this.clone().ineg();
      }, a.prototype.ineg = function() {
        return this.isZero() || (this.negative ^= 1), this;
      }, a.prototype.iuor = function(n) {
        for (; this.length < n.length; )
          this.words[this.length++] = 0;
        for (var s = 0; s < n.length; s++)
          this.words[s] = this.words[s] | n.words[s];
        return this._strip();
      }, a.prototype.ior = function(n) {
        return i((this.negative | n.negative) === 0), this.iuor(n);
      }, a.prototype.or = function(n) {
        return this.length > n.length ? this.clone().ior(n) : n.clone().ior(this);
      }, a.prototype.uor = function(n) {
        return this.length > n.length ? this.clone().iuor(n) : n.clone().iuor(this);
      }, a.prototype.iuand = function(n) {
        var s;
        this.length > n.length ? s = n : s = this;
        for (var d = 0; d < s.length; d++)
          this.words[d] = this.words[d] & n.words[d];
        return this.length = s.length, this._strip();
      }, a.prototype.iand = function(n) {
        return i((this.negative | n.negative) === 0), this.iuand(n);
      }, a.prototype.and = function(n) {
        return this.length > n.length ? this.clone().iand(n) : n.clone().iand(this);
      }, a.prototype.uand = function(n) {
        return this.length > n.length ? this.clone().iuand(n) : n.clone().iuand(this);
      }, a.prototype.iuxor = function(n) {
        var s, d;
        this.length > n.length ? (s = this, d = n) : (s = n, d = this);
        for (var w = 0; w < d.length; w++)
          this.words[w] = s.words[w] ^ d.words[w];
        if (this !== s)
          for (; w < s.length; w++)
            this.words[w] = s.words[w];
        return this.length = s.length, this._strip();
      }, a.prototype.ixor = function(n) {
        return i((this.negative | n.negative) === 0), this.iuxor(n);
      }, a.prototype.xor = function(n) {
        return this.length > n.length ? this.clone().ixor(n) : n.clone().ixor(this);
      }, a.prototype.uxor = function(n) {
        return this.length > n.length ? this.clone().iuxor(n) : n.clone().iuxor(this);
      }, a.prototype.inotn = function(n) {
        i(typeof n == "number" && n >= 0);
        var s = Math.ceil(n / 26) | 0, d = n % 26;
        this._expand(s), d > 0 && s--;
        for (var w = 0; w < s; w++)
          this.words[w] = ~this.words[w] & 67108863;
        return d > 0 && (this.words[w] = ~this.words[w] & 67108863 >> 26 - d), this._strip();
      }, a.prototype.notn = function(n) {
        return this.clone().inotn(n);
      }, a.prototype.setn = function(n, s) {
        i(typeof n == "number" && n >= 0);
        var d = n / 26 | 0, w = n % 26;
        return this._expand(d + 1), s ? this.words[d] = this.words[d] | 1 << w : this.words[d] = this.words[d] & ~(1 << w), this._strip();
      }, a.prototype.iadd = function(n) {
        var s;
        if (this.negative !== 0 && n.negative === 0)
          return this.negative = 0, s = this.isub(n), this.negative ^= 1, this._normSign();
        if (this.negative === 0 && n.negative !== 0)
          return n.negative = 0, s = this.isub(n), n.negative = 1, s._normSign();
        var d, w;
        this.length > n.length ? (d = this, w = n) : (d = n, w = this);
        for (var A = 0, k = 0; k < w.length; k++)
          s = (d.words[k] | 0) + (w.words[k] | 0) + A, this.words[k] = s & 67108863, A = s >>> 26;
        for (; A !== 0 && k < d.length; k++)
          s = (d.words[k] | 0) + A, this.words[k] = s & 67108863, A = s >>> 26;
        if (this.length = d.length, A !== 0)
          this.words[this.length] = A, this.length++;
        else if (d !== this)
          for (; k < d.length; k++)
            this.words[k] = d.words[k];
        return this;
      }, a.prototype.add = function(n) {
        var s;
        return n.negative !== 0 && this.negative === 0 ? (n.negative = 0, s = this.sub(n), n.negative ^= 1, s) : n.negative === 0 && this.negative !== 0 ? (this.negative = 0, s = n.sub(this), this.negative = 1, s) : this.length > n.length ? this.clone().iadd(n) : n.clone().iadd(this);
      }, a.prototype.isub = function(n) {
        if (n.negative !== 0) {
          n.negative = 0;
          var s = this.iadd(n);
          return n.negative = 1, s._normSign();
        } else if (this.negative !== 0)
          return this.negative = 0, this.iadd(n), this.negative = 1, this._normSign();
        var d = this.cmp(n);
        if (d === 0)
          return this.negative = 0, this.length = 1, this.words[0] = 0, this;
        var w, A;
        d > 0 ? (w = this, A = n) : (w = n, A = this);
        for (var k = 0, l = 0; l < A.length; l++)
          s = (w.words[l] | 0) - (A.words[l] | 0) + k, k = s >> 26, this.words[l] = s & 67108863;
        for (; k !== 0 && l < w.length; l++)
          s = (w.words[l] | 0) + k, k = s >> 26, this.words[l] = s & 67108863;
        if (k === 0 && l < w.length && w !== this)
          for (; l < w.length; l++)
            this.words[l] = w.words[l];
        return this.length = Math.max(this.length, l), w !== this && (this.negative = 1), this._strip();
      }, a.prototype.sub = function(n) {
        return this.clone().isub(n);
      };
      function N(u, n, s) {
        s.negative = n.negative ^ u.negative;
        var d = u.length + n.length | 0;
        s.length = d, d = d - 1 | 0;
        var w = u.words[0] | 0, A = n.words[0] | 0, k = w * A, l = k & 67108863, y = k / 67108864 | 0;
        s.words[0] = l;
        for (var v = 1; v < d; v++) {
          for (var P = y >>> 26, J = y & 67108863, Y = Math.min(v, n.length - 1), Q = Math.max(0, v - u.length + 1); Q <= Y; Q++) {
            var se = v - Q | 0;
            w = u.words[se] | 0, A = n.words[Q] | 0, k = w * A + J, P += k / 67108864 | 0, J = k & 67108863;
          }
          s.words[v] = J | 0, y = P | 0;
        }
        return y !== 0 ? s.words[v] = y | 0 : s.length--, s._strip();
      }
      var U = function(n, s, d) {
        var w = n.words, A = s.words, k = d.words, l = 0, y, v, P, J = w[0] | 0, Y = J & 8191, Q = J >>> 13, se = w[1] | 0, pe = se & 8191, ne = se >>> 13, Ne = w[2] | 0, qe = Ne & 8191, he = Ne >>> 13, Ee = w[3] | 0, Ce = Ee & 8191, fe = Ee >>> 13, Re = w[4] | 0, Fe = Re & 8191, me = Re >>> 13, He = w[5] | 0, De = He & 8191, ce = He >>> 13, Pe = w[6] | 0, je = Pe & 8191, de = Pe >>> 13, Te = w[7] | 0, Ve = Te & 8191, B = Te >>> 13, b = w[8] | 0, x = b & 8191, T = b >>> 13, L = w[9] | 0, D = L & 8191, H = L >>> 13, ae = A[0] | 0, be = ae & 8191, ie = ae >>> 13, ve = A[1] | 0, ue = ve & 8191, we = ve >>> 13, $e = A[2] | 0, et = $e & 8191, xe = $e >>> 13, tt = A[3] | 0, rt = tt & 8191, ke = tt >>> 13, it = A[4] | 0, at = it & 8191, Se = it >>> 13, nt = A[5] | 0, ot = nt & 8191, Ae = nt >>> 13, st = A[6] | 0, ut = st & 8191, _e = st >>> 13, ft = A[7] | 0, ct = ft & 8191, Me = ft >>> 13, lt = A[8] | 0, ht = lt & 8191, Be = lt >>> 13, dt = A[9] | 0, Ze = dt & 8191, Qe = dt >>> 13;
        d.negative = n.negative ^ s.negative, d.length = 19, y = Math.imul(Y, be), v = Math.imul(Y, ie), v = v + Math.imul(Q, be) | 0, P = Math.imul(Q, ie);
        var gr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (gr >>> 26) | 0, gr &= 67108863, y = Math.imul(pe, be), v = Math.imul(pe, ie), v = v + Math.imul(ne, be) | 0, P = Math.imul(ne, ie), y = y + Math.imul(Y, ue) | 0, v = v + Math.imul(Y, we) | 0, v = v + Math.imul(Q, ue) | 0, P = P + Math.imul(Q, we) | 0;
        var yr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (yr >>> 26) | 0, yr &= 67108863, y = Math.imul(qe, be), v = Math.imul(qe, ie), v = v + Math.imul(he, be) | 0, P = Math.imul(he, ie), y = y + Math.imul(pe, ue) | 0, v = v + Math.imul(pe, we) | 0, v = v + Math.imul(ne, ue) | 0, P = P + Math.imul(ne, we) | 0, y = y + Math.imul(Y, et) | 0, v = v + Math.imul(Y, xe) | 0, v = v + Math.imul(Q, et) | 0, P = P + Math.imul(Q, xe) | 0;
        var wr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (wr >>> 26) | 0, wr &= 67108863, y = Math.imul(Ce, be), v = Math.imul(Ce, ie), v = v + Math.imul(fe, be) | 0, P = Math.imul(fe, ie), y = y + Math.imul(qe, ue) | 0, v = v + Math.imul(qe, we) | 0, v = v + Math.imul(he, ue) | 0, P = P + Math.imul(he, we) | 0, y = y + Math.imul(pe, et) | 0, v = v + Math.imul(pe, xe) | 0, v = v + Math.imul(ne, et) | 0, P = P + Math.imul(ne, xe) | 0, y = y + Math.imul(Y, rt) | 0, v = v + Math.imul(Y, ke) | 0, v = v + Math.imul(Q, rt) | 0, P = P + Math.imul(Q, ke) | 0;
        var xr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (xr >>> 26) | 0, xr &= 67108863, y = Math.imul(Fe, be), v = Math.imul(Fe, ie), v = v + Math.imul(me, be) | 0, P = Math.imul(me, ie), y = y + Math.imul(Ce, ue) | 0, v = v + Math.imul(Ce, we) | 0, v = v + Math.imul(fe, ue) | 0, P = P + Math.imul(fe, we) | 0, y = y + Math.imul(qe, et) | 0, v = v + Math.imul(qe, xe) | 0, v = v + Math.imul(he, et) | 0, P = P + Math.imul(he, xe) | 0, y = y + Math.imul(pe, rt) | 0, v = v + Math.imul(pe, ke) | 0, v = v + Math.imul(ne, rt) | 0, P = P + Math.imul(ne, ke) | 0, y = y + Math.imul(Y, at) | 0, v = v + Math.imul(Y, Se) | 0, v = v + Math.imul(Q, at) | 0, P = P + Math.imul(Q, Se) | 0;
        var kr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (kr >>> 26) | 0, kr &= 67108863, y = Math.imul(De, be), v = Math.imul(De, ie), v = v + Math.imul(ce, be) | 0, P = Math.imul(ce, ie), y = y + Math.imul(Fe, ue) | 0, v = v + Math.imul(Fe, we) | 0, v = v + Math.imul(me, ue) | 0, P = P + Math.imul(me, we) | 0, y = y + Math.imul(Ce, et) | 0, v = v + Math.imul(Ce, xe) | 0, v = v + Math.imul(fe, et) | 0, P = P + Math.imul(fe, xe) | 0, y = y + Math.imul(qe, rt) | 0, v = v + Math.imul(qe, ke) | 0, v = v + Math.imul(he, rt) | 0, P = P + Math.imul(he, ke) | 0, y = y + Math.imul(pe, at) | 0, v = v + Math.imul(pe, Se) | 0, v = v + Math.imul(ne, at) | 0, P = P + Math.imul(ne, Se) | 0, y = y + Math.imul(Y, ot) | 0, v = v + Math.imul(Y, Ae) | 0, v = v + Math.imul(Q, ot) | 0, P = P + Math.imul(Q, Ae) | 0;
        var Sr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Sr >>> 26) | 0, Sr &= 67108863, y = Math.imul(je, be), v = Math.imul(je, ie), v = v + Math.imul(de, be) | 0, P = Math.imul(de, ie), y = y + Math.imul(De, ue) | 0, v = v + Math.imul(De, we) | 0, v = v + Math.imul(ce, ue) | 0, P = P + Math.imul(ce, we) | 0, y = y + Math.imul(Fe, et) | 0, v = v + Math.imul(Fe, xe) | 0, v = v + Math.imul(me, et) | 0, P = P + Math.imul(me, xe) | 0, y = y + Math.imul(Ce, rt) | 0, v = v + Math.imul(Ce, ke) | 0, v = v + Math.imul(fe, rt) | 0, P = P + Math.imul(fe, ke) | 0, y = y + Math.imul(qe, at) | 0, v = v + Math.imul(qe, Se) | 0, v = v + Math.imul(he, at) | 0, P = P + Math.imul(he, Se) | 0, y = y + Math.imul(pe, ot) | 0, v = v + Math.imul(pe, Ae) | 0, v = v + Math.imul(ne, ot) | 0, P = P + Math.imul(ne, Ae) | 0, y = y + Math.imul(Y, ut) | 0, v = v + Math.imul(Y, _e) | 0, v = v + Math.imul(Q, ut) | 0, P = P + Math.imul(Q, _e) | 0;
        var Ar = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Ar >>> 26) | 0, Ar &= 67108863, y = Math.imul(Ve, be), v = Math.imul(Ve, ie), v = v + Math.imul(B, be) | 0, P = Math.imul(B, ie), y = y + Math.imul(je, ue) | 0, v = v + Math.imul(je, we) | 0, v = v + Math.imul(de, ue) | 0, P = P + Math.imul(de, we) | 0, y = y + Math.imul(De, et) | 0, v = v + Math.imul(De, xe) | 0, v = v + Math.imul(ce, et) | 0, P = P + Math.imul(ce, xe) | 0, y = y + Math.imul(Fe, rt) | 0, v = v + Math.imul(Fe, ke) | 0, v = v + Math.imul(me, rt) | 0, P = P + Math.imul(me, ke) | 0, y = y + Math.imul(Ce, at) | 0, v = v + Math.imul(Ce, Se) | 0, v = v + Math.imul(fe, at) | 0, P = P + Math.imul(fe, Se) | 0, y = y + Math.imul(qe, ot) | 0, v = v + Math.imul(qe, Ae) | 0, v = v + Math.imul(he, ot) | 0, P = P + Math.imul(he, Ae) | 0, y = y + Math.imul(pe, ut) | 0, v = v + Math.imul(pe, _e) | 0, v = v + Math.imul(ne, ut) | 0, P = P + Math.imul(ne, _e) | 0, y = y + Math.imul(Y, ct) | 0, v = v + Math.imul(Y, Me) | 0, v = v + Math.imul(Q, ct) | 0, P = P + Math.imul(Q, Me) | 0;
        var _r = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (_r >>> 26) | 0, _r &= 67108863, y = Math.imul(x, be), v = Math.imul(x, ie), v = v + Math.imul(T, be) | 0, P = Math.imul(T, ie), y = y + Math.imul(Ve, ue) | 0, v = v + Math.imul(Ve, we) | 0, v = v + Math.imul(B, ue) | 0, P = P + Math.imul(B, we) | 0, y = y + Math.imul(je, et) | 0, v = v + Math.imul(je, xe) | 0, v = v + Math.imul(de, et) | 0, P = P + Math.imul(de, xe) | 0, y = y + Math.imul(De, rt) | 0, v = v + Math.imul(De, ke) | 0, v = v + Math.imul(ce, rt) | 0, P = P + Math.imul(ce, ke) | 0, y = y + Math.imul(Fe, at) | 0, v = v + Math.imul(Fe, Se) | 0, v = v + Math.imul(me, at) | 0, P = P + Math.imul(me, Se) | 0, y = y + Math.imul(Ce, ot) | 0, v = v + Math.imul(Ce, Ae) | 0, v = v + Math.imul(fe, ot) | 0, P = P + Math.imul(fe, Ae) | 0, y = y + Math.imul(qe, ut) | 0, v = v + Math.imul(qe, _e) | 0, v = v + Math.imul(he, ut) | 0, P = P + Math.imul(he, _e) | 0, y = y + Math.imul(pe, ct) | 0, v = v + Math.imul(pe, Me) | 0, v = v + Math.imul(ne, ct) | 0, P = P + Math.imul(ne, Me) | 0, y = y + Math.imul(Y, ht) | 0, v = v + Math.imul(Y, Be) | 0, v = v + Math.imul(Q, ht) | 0, P = P + Math.imul(Q, Be) | 0;
        var Mr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Mr >>> 26) | 0, Mr &= 67108863, y = Math.imul(D, be), v = Math.imul(D, ie), v = v + Math.imul(H, be) | 0, P = Math.imul(H, ie), y = y + Math.imul(x, ue) | 0, v = v + Math.imul(x, we) | 0, v = v + Math.imul(T, ue) | 0, P = P + Math.imul(T, we) | 0, y = y + Math.imul(Ve, et) | 0, v = v + Math.imul(Ve, xe) | 0, v = v + Math.imul(B, et) | 0, P = P + Math.imul(B, xe) | 0, y = y + Math.imul(je, rt) | 0, v = v + Math.imul(je, ke) | 0, v = v + Math.imul(de, rt) | 0, P = P + Math.imul(de, ke) | 0, y = y + Math.imul(De, at) | 0, v = v + Math.imul(De, Se) | 0, v = v + Math.imul(ce, at) | 0, P = P + Math.imul(ce, Se) | 0, y = y + Math.imul(Fe, ot) | 0, v = v + Math.imul(Fe, Ae) | 0, v = v + Math.imul(me, ot) | 0, P = P + Math.imul(me, Ae) | 0, y = y + Math.imul(Ce, ut) | 0, v = v + Math.imul(Ce, _e) | 0, v = v + Math.imul(fe, ut) | 0, P = P + Math.imul(fe, _e) | 0, y = y + Math.imul(qe, ct) | 0, v = v + Math.imul(qe, Me) | 0, v = v + Math.imul(he, ct) | 0, P = P + Math.imul(he, Me) | 0, y = y + Math.imul(pe, ht) | 0, v = v + Math.imul(pe, Be) | 0, v = v + Math.imul(ne, ht) | 0, P = P + Math.imul(ne, Be) | 0, y = y + Math.imul(Y, Ze) | 0, v = v + Math.imul(Y, Qe) | 0, v = v + Math.imul(Q, Ze) | 0, P = P + Math.imul(Q, Qe) | 0;
        var Br = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Br >>> 26) | 0, Br &= 67108863, y = Math.imul(D, ue), v = Math.imul(D, we), v = v + Math.imul(H, ue) | 0, P = Math.imul(H, we), y = y + Math.imul(x, et) | 0, v = v + Math.imul(x, xe) | 0, v = v + Math.imul(T, et) | 0, P = P + Math.imul(T, xe) | 0, y = y + Math.imul(Ve, rt) | 0, v = v + Math.imul(Ve, ke) | 0, v = v + Math.imul(B, rt) | 0, P = P + Math.imul(B, ke) | 0, y = y + Math.imul(je, at) | 0, v = v + Math.imul(je, Se) | 0, v = v + Math.imul(de, at) | 0, P = P + Math.imul(de, Se) | 0, y = y + Math.imul(De, ot) | 0, v = v + Math.imul(De, Ae) | 0, v = v + Math.imul(ce, ot) | 0, P = P + Math.imul(ce, Ae) | 0, y = y + Math.imul(Fe, ut) | 0, v = v + Math.imul(Fe, _e) | 0, v = v + Math.imul(me, ut) | 0, P = P + Math.imul(me, _e) | 0, y = y + Math.imul(Ce, ct) | 0, v = v + Math.imul(Ce, Me) | 0, v = v + Math.imul(fe, ct) | 0, P = P + Math.imul(fe, Me) | 0, y = y + Math.imul(qe, ht) | 0, v = v + Math.imul(qe, Be) | 0, v = v + Math.imul(he, ht) | 0, P = P + Math.imul(he, Be) | 0, y = y + Math.imul(pe, Ze) | 0, v = v + Math.imul(pe, Qe) | 0, v = v + Math.imul(ne, Ze) | 0, P = P + Math.imul(ne, Qe) | 0;
        var Ir = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Ir >>> 26) | 0, Ir &= 67108863, y = Math.imul(D, et), v = Math.imul(D, xe), v = v + Math.imul(H, et) | 0, P = Math.imul(H, xe), y = y + Math.imul(x, rt) | 0, v = v + Math.imul(x, ke) | 0, v = v + Math.imul(T, rt) | 0, P = P + Math.imul(T, ke) | 0, y = y + Math.imul(Ve, at) | 0, v = v + Math.imul(Ve, Se) | 0, v = v + Math.imul(B, at) | 0, P = P + Math.imul(B, Se) | 0, y = y + Math.imul(je, ot) | 0, v = v + Math.imul(je, Ae) | 0, v = v + Math.imul(de, ot) | 0, P = P + Math.imul(de, Ae) | 0, y = y + Math.imul(De, ut) | 0, v = v + Math.imul(De, _e) | 0, v = v + Math.imul(ce, ut) | 0, P = P + Math.imul(ce, _e) | 0, y = y + Math.imul(Fe, ct) | 0, v = v + Math.imul(Fe, Me) | 0, v = v + Math.imul(me, ct) | 0, P = P + Math.imul(me, Me) | 0, y = y + Math.imul(Ce, ht) | 0, v = v + Math.imul(Ce, Be) | 0, v = v + Math.imul(fe, ht) | 0, P = P + Math.imul(fe, Be) | 0, y = y + Math.imul(qe, Ze) | 0, v = v + Math.imul(qe, Qe) | 0, v = v + Math.imul(he, Ze) | 0, P = P + Math.imul(he, Qe) | 0;
        var Er = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Er >>> 26) | 0, Er &= 67108863, y = Math.imul(D, rt), v = Math.imul(D, ke), v = v + Math.imul(H, rt) | 0, P = Math.imul(H, ke), y = y + Math.imul(x, at) | 0, v = v + Math.imul(x, Se) | 0, v = v + Math.imul(T, at) | 0, P = P + Math.imul(T, Se) | 0, y = y + Math.imul(Ve, ot) | 0, v = v + Math.imul(Ve, Ae) | 0, v = v + Math.imul(B, ot) | 0, P = P + Math.imul(B, Ae) | 0, y = y + Math.imul(je, ut) | 0, v = v + Math.imul(je, _e) | 0, v = v + Math.imul(de, ut) | 0, P = P + Math.imul(de, _e) | 0, y = y + Math.imul(De, ct) | 0, v = v + Math.imul(De, Me) | 0, v = v + Math.imul(ce, ct) | 0, P = P + Math.imul(ce, Me) | 0, y = y + Math.imul(Fe, ht) | 0, v = v + Math.imul(Fe, Be) | 0, v = v + Math.imul(me, ht) | 0, P = P + Math.imul(me, Be) | 0, y = y + Math.imul(Ce, Ze) | 0, v = v + Math.imul(Ce, Qe) | 0, v = v + Math.imul(fe, Ze) | 0, P = P + Math.imul(fe, Qe) | 0;
        var Pr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Pr >>> 26) | 0, Pr &= 67108863, y = Math.imul(D, at), v = Math.imul(D, Se), v = v + Math.imul(H, at) | 0, P = Math.imul(H, Se), y = y + Math.imul(x, ot) | 0, v = v + Math.imul(x, Ae) | 0, v = v + Math.imul(T, ot) | 0, P = P + Math.imul(T, Ae) | 0, y = y + Math.imul(Ve, ut) | 0, v = v + Math.imul(Ve, _e) | 0, v = v + Math.imul(B, ut) | 0, P = P + Math.imul(B, _e) | 0, y = y + Math.imul(je, ct) | 0, v = v + Math.imul(je, Me) | 0, v = v + Math.imul(de, ct) | 0, P = P + Math.imul(de, Me) | 0, y = y + Math.imul(De, ht) | 0, v = v + Math.imul(De, Be) | 0, v = v + Math.imul(ce, ht) | 0, P = P + Math.imul(ce, Be) | 0, y = y + Math.imul(Fe, Ze) | 0, v = v + Math.imul(Fe, Qe) | 0, v = v + Math.imul(me, Ze) | 0, P = P + Math.imul(me, Qe) | 0;
        var Tr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Tr >>> 26) | 0, Tr &= 67108863, y = Math.imul(D, ot), v = Math.imul(D, Ae), v = v + Math.imul(H, ot) | 0, P = Math.imul(H, Ae), y = y + Math.imul(x, ut) | 0, v = v + Math.imul(x, _e) | 0, v = v + Math.imul(T, ut) | 0, P = P + Math.imul(T, _e) | 0, y = y + Math.imul(Ve, ct) | 0, v = v + Math.imul(Ve, Me) | 0, v = v + Math.imul(B, ct) | 0, P = P + Math.imul(B, Me) | 0, y = y + Math.imul(je, ht) | 0, v = v + Math.imul(je, Be) | 0, v = v + Math.imul(de, ht) | 0, P = P + Math.imul(de, Be) | 0, y = y + Math.imul(De, Ze) | 0, v = v + Math.imul(De, Qe) | 0, v = v + Math.imul(ce, Ze) | 0, P = P + Math.imul(ce, Qe) | 0;
        var zr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (zr >>> 26) | 0, zr &= 67108863, y = Math.imul(D, ut), v = Math.imul(D, _e), v = v + Math.imul(H, ut) | 0, P = Math.imul(H, _e), y = y + Math.imul(x, ct) | 0, v = v + Math.imul(x, Me) | 0, v = v + Math.imul(T, ct) | 0, P = P + Math.imul(T, Me) | 0, y = y + Math.imul(Ve, ht) | 0, v = v + Math.imul(Ve, Be) | 0, v = v + Math.imul(B, ht) | 0, P = P + Math.imul(B, Be) | 0, y = y + Math.imul(je, Ze) | 0, v = v + Math.imul(je, Qe) | 0, v = v + Math.imul(de, Ze) | 0, P = P + Math.imul(de, Qe) | 0;
        var Or = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Or >>> 26) | 0, Or &= 67108863, y = Math.imul(D, ct), v = Math.imul(D, Me), v = v + Math.imul(H, ct) | 0, P = Math.imul(H, Me), y = y + Math.imul(x, ht) | 0, v = v + Math.imul(x, Be) | 0, v = v + Math.imul(T, ht) | 0, P = P + Math.imul(T, Be) | 0, y = y + Math.imul(Ve, Ze) | 0, v = v + Math.imul(Ve, Qe) | 0, v = v + Math.imul(B, Ze) | 0, P = P + Math.imul(B, Qe) | 0;
        var Nr = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Nr >>> 26) | 0, Nr &= 67108863, y = Math.imul(D, ht), v = Math.imul(D, Be), v = v + Math.imul(H, ht) | 0, P = Math.imul(H, Be), y = y + Math.imul(x, Ze) | 0, v = v + Math.imul(x, Qe) | 0, v = v + Math.imul(T, Ze) | 0, P = P + Math.imul(T, Qe) | 0;
        var Di = (l + y | 0) + ((v & 8191) << 13) | 0;
        l = (P + (v >>> 13) | 0) + (Di >>> 26) | 0, Di &= 67108863, y = Math.imul(D, Ze), v = Math.imul(D, Qe), v = v + Math.imul(H, Ze) | 0, P = Math.imul(H, Qe);
        var Hi = (l + y | 0) + ((v & 8191) << 13) | 0;
        return l = (P + (v >>> 13) | 0) + (Hi >>> 26) | 0, Hi &= 67108863, k[0] = gr, k[1] = yr, k[2] = wr, k[3] = xr, k[4] = kr, k[5] = Sr, k[6] = Ar, k[7] = _r, k[8] = Mr, k[9] = Br, k[10] = Ir, k[11] = Er, k[12] = Pr, k[13] = Tr, k[14] = zr, k[15] = Or, k[16] = Nr, k[17] = Di, k[18] = Hi, l !== 0 && (k[19] = l, d.length++), d;
      };
      Math.imul || (U = N);
      function j(u, n, s) {
        s.negative = n.negative ^ u.negative, s.length = u.length + n.length;
        for (var d = 0, w = 0, A = 0; A < s.length - 1; A++) {
          var k = w;
          w = 0;
          for (var l = d & 67108863, y = Math.min(A, n.length - 1), v = Math.max(0, A - u.length + 1); v <= y; v++) {
            var P = A - v, J = u.words[P] | 0, Y = n.words[v] | 0, Q = J * Y, se = Q & 67108863;
            k = k + (Q / 67108864 | 0) | 0, se = se + l | 0, l = se & 67108863, k = k + (se >>> 26) | 0, w += k >>> 26, k &= 67108863;
          }
          s.words[A] = l, d = k, k = w;
        }
        return d !== 0 ? s.words[A] = d : s.length--, s._strip();
      }
      function F(u, n, s) {
        return j(u, n, s);
      }
      a.prototype.mulTo = function(n, s) {
        var d, w = this.length + n.length;
        return this.length === 10 && n.length === 10 ? d = U(this, n, s) : w < 63 ? d = N(this, n, s) : w < 1024 ? d = j(this, n, s) : d = F(this, n, s), d;
      }, a.prototype.mul = function(n) {
        var s = new a(null);
        return s.words = new Array(this.length + n.length), this.mulTo(n, s);
      }, a.prototype.mulf = function(n) {
        var s = new a(null);
        return s.words = new Array(this.length + n.length), F(this, n, s);
      }, a.prototype.imul = function(n) {
        return this.clone().mulTo(n, this);
      }, a.prototype.imuln = function(n) {
        var s = n < 0;
        s && (n = -n), i(typeof n == "number"), i(n < 67108864);
        for (var d = 0, w = 0; w < this.length; w++) {
          var A = (this.words[w] | 0) * n, k = (A & 67108863) + (d & 67108863);
          d >>= 26, d += A / 67108864 | 0, d += k >>> 26, this.words[w] = k & 67108863;
        }
        return d !== 0 && (this.words[w] = d, this.length++), this.length = n === 0 ? 1 : this.length, s ? this.ineg() : this;
      }, a.prototype.muln = function(n) {
        return this.clone().imuln(n);
      }, a.prototype.sqr = function() {
        return this.mul(this);
      }, a.prototype.isqr = function() {
        return this.imul(this.clone());
      }, a.prototype.pow = function(n) {
        var s = O(n);
        if (s.length === 0) return new a(1);
        for (var d = this, w = 0; w < s.length && s[w] === 0; w++, d = d.sqr())
          ;
        if (++w < s.length)
          for (var A = d.sqr(); w < s.length; w++, A = A.sqr())
            s[w] !== 0 && (d = d.mul(A));
        return d;
      }, a.prototype.iushln = function(n) {
        i(typeof n == "number" && n >= 0);
        var s = n % 26, d = (n - s) / 26, w = 67108863 >>> 26 - s << 26 - s, A;
        if (s !== 0) {
          var k = 0;
          for (A = 0; A < this.length; A++) {
            var l = this.words[A] & w, y = (this.words[A] | 0) - l << s;
            this.words[A] = y | k, k = l >>> 26 - s;
          }
          k && (this.words[A] = k, this.length++);
        }
        if (d !== 0) {
          for (A = this.length - 1; A >= 0; A--)
            this.words[A + d] = this.words[A];
          for (A = 0; A < d; A++)
            this.words[A] = 0;
          this.length += d;
        }
        return this._strip();
      }, a.prototype.ishln = function(n) {
        return i(this.negative === 0), this.iushln(n);
      }, a.prototype.iushrn = function(n, s, d) {
        i(typeof n == "number" && n >= 0);
        var w;
        s ? w = (s - s % 26) / 26 : w = 0;
        var A = n % 26, k = Math.min((n - A) / 26, this.length), l = 67108863 ^ 67108863 >>> A << A, y = d;
        if (w -= k, w = Math.max(0, w), y) {
          for (var v = 0; v < k; v++)
            y.words[v] = this.words[v];
          y.length = k;
        }
        if (k !== 0) if (this.length > k)
          for (this.length -= k, v = 0; v < this.length; v++)
            this.words[v] = this.words[v + k];
        else
          this.words[0] = 0, this.length = 1;
        var P = 0;
        for (v = this.length - 1; v >= 0 && (P !== 0 || v >= w); v--) {
          var J = this.words[v] | 0;
          this.words[v] = P << 26 - A | J >>> A, P = J & l;
        }
        return y && P !== 0 && (y.words[y.length++] = P), this.length === 0 && (this.words[0] = 0, this.length = 1), this._strip();
      }, a.prototype.ishrn = function(n, s, d) {
        return i(this.negative === 0), this.iushrn(n, s, d);
      }, a.prototype.shln = function(n) {
        return this.clone().ishln(n);
      }, a.prototype.ushln = function(n) {
        return this.clone().iushln(n);
      }, a.prototype.shrn = function(n) {
        return this.clone().ishrn(n);
      }, a.prototype.ushrn = function(n) {
        return this.clone().iushrn(n);
      }, a.prototype.testn = function(n) {
        i(typeof n == "number" && n >= 0);
        var s = n % 26, d = (n - s) / 26, w = 1 << s;
        if (this.length <= d) return !1;
        var A = this.words[d];
        return !!(A & w);
      }, a.prototype.imaskn = function(n) {
        i(typeof n == "number" && n >= 0);
        var s = n % 26, d = (n - s) / 26;
        if (i(this.negative === 0, "imaskn works only with positive numbers"), this.length <= d)
          return this;
        if (s !== 0 && d++, this.length = Math.min(d, this.length), s !== 0) {
          var w = 67108863 ^ 67108863 >>> s << s;
          this.words[this.length - 1] &= w;
        }
        return this._strip();
      }, a.prototype.maskn = function(n) {
        return this.clone().imaskn(n);
      }, a.prototype.iaddn = function(n) {
        return i(typeof n == "number"), i(n < 67108864), n < 0 ? this.isubn(-n) : this.negative !== 0 ? this.length === 1 && (this.words[0] | 0) <= n ? (this.words[0] = n - (this.words[0] | 0), this.negative = 0, this) : (this.negative = 0, this.isubn(n), this.negative = 1, this) : this._iaddn(n);
      }, a.prototype._iaddn = function(n) {
        this.words[0] += n;
        for (var s = 0; s < this.length && this.words[s] >= 67108864; s++)
          this.words[s] -= 67108864, s === this.length - 1 ? this.words[s + 1] = 1 : this.words[s + 1]++;
        return this.length = Math.max(this.length, s + 1), this;
      }, a.prototype.isubn = function(n) {
        if (i(typeof n == "number"), i(n < 67108864), n < 0) return this.iaddn(-n);
        if (this.negative !== 0)
          return this.negative = 0, this.iaddn(n), this.negative = 1, this;
        if (this.words[0] -= n, this.length === 1 && this.words[0] < 0)
          this.words[0] = -this.words[0], this.negative = 1;
        else
          for (var s = 0; s < this.length && this.words[s] < 0; s++)
            this.words[s] += 67108864, this.words[s + 1] -= 1;
        return this._strip();
      }, a.prototype.addn = function(n) {
        return this.clone().iaddn(n);
      }, a.prototype.subn = function(n) {
        return this.clone().isubn(n);
      }, a.prototype.iabs = function() {
        return this.negative = 0, this;
      }, a.prototype.abs = function() {
        return this.clone().iabs();
      }, a.prototype._ishlnsubmul = function(n, s, d) {
        var w = n.length + d, A;
        this._expand(w);
        var k, l = 0;
        for (A = 0; A < n.length; A++) {
          k = (this.words[A + d] | 0) + l;
          var y = (n.words[A] | 0) * s;
          k -= y & 67108863, l = (k >> 26) - (y / 67108864 | 0), this.words[A + d] = k & 67108863;
        }
        for (; A < this.length - d; A++)
          k = (this.words[A + d] | 0) + l, l = k >> 26, this.words[A + d] = k & 67108863;
        if (l === 0) return this._strip();
        for (i(l === -1), l = 0, A = 0; A < this.length; A++)
          k = -(this.words[A] | 0) + l, l = k >> 26, this.words[A] = k & 67108863;
        return this.negative = 1, this._strip();
      }, a.prototype._wordDiv = function(n, s) {
        var d = this.length - n.length, w = this.clone(), A = n, k = A.words[A.length - 1] | 0, l = this._countBits(k);
        d = 26 - l, d !== 0 && (A = A.ushln(d), w.iushln(d), k = A.words[A.length - 1] | 0);
        var y = w.length - A.length, v;
        if (s !== "mod") {
          v = new a(null), v.length = y + 1, v.words = new Array(v.length);
          for (var P = 0; P < v.length; P++)
            v.words[P] = 0;
        }
        var J = w.clone()._ishlnsubmul(A, 1, y);
        J.negative === 0 && (w = J, v && (v.words[y] = 1));
        for (var Y = y - 1; Y >= 0; Y--) {
          var Q = (w.words[A.length + Y] | 0) * 67108864 + (w.words[A.length + Y - 1] | 0);
          for (Q = Math.min(Q / k | 0, 67108863), w._ishlnsubmul(A, Q, Y); w.negative !== 0; )
            Q--, w.negative = 0, w._ishlnsubmul(A, 1, Y), w.isZero() || (w.negative ^= 1);
          v && (v.words[Y] = Q);
        }
        return v && v._strip(), w._strip(), s !== "div" && d !== 0 && w.iushrn(d), {
          div: v || null,
          mod: w
        };
      }, a.prototype.divmod = function(n, s, d) {
        if (i(!n.isZero()), this.isZero())
          return {
            div: new a(0),
            mod: new a(0)
          };
        var w, A, k;
        return this.negative !== 0 && n.negative === 0 ? (k = this.neg().divmod(n, s), s !== "mod" && (w = k.div.neg()), s !== "div" && (A = k.mod.neg(), d && A.negative !== 0 && A.iadd(n)), {
          div: w,
          mod: A
        }) : this.negative === 0 && n.negative !== 0 ? (k = this.divmod(n.neg(), s), s !== "mod" && (w = k.div.neg()), {
          div: w,
          mod: k.mod
        }) : (this.negative & n.negative) !== 0 ? (k = this.neg().divmod(n.neg(), s), s !== "div" && (A = k.mod.neg(), d && A.negative !== 0 && A.isub(n)), {
          div: k.div,
          mod: A
        }) : n.length > this.length || this.cmp(n) < 0 ? {
          div: new a(0),
          mod: this
        } : n.length === 1 ? s === "div" ? {
          div: this.divn(n.words[0]),
          mod: null
        } : s === "mod" ? {
          div: null,
          mod: new a(this.modrn(n.words[0]))
        } : {
          div: this.divn(n.words[0]),
          mod: new a(this.modrn(n.words[0]))
        } : this._wordDiv(n, s);
      }, a.prototype.div = function(n) {
        return this.divmod(n, "div", !1).div;
      }, a.prototype.mod = function(n) {
        return this.divmod(n, "mod", !1).mod;
      }, a.prototype.umod = function(n) {
        return this.divmod(n, "mod", !0).mod;
      }, a.prototype.divRound = function(n) {
        var s = this.divmod(n);
        if (s.mod.isZero()) return s.div;
        var d = s.div.negative !== 0 ? s.mod.isub(n) : s.mod, w = n.ushrn(1), A = n.andln(1), k = d.cmp(w);
        return k < 0 || A === 1 && k === 0 ? s.div : s.div.negative !== 0 ? s.div.isubn(1) : s.div.iaddn(1);
      }, a.prototype.modrn = function(n) {
        var s = n < 0;
        s && (n = -n), i(n <= 67108863);
        for (var d = (1 << 26) % n, w = 0, A = this.length - 1; A >= 0; A--)
          w = (d * w + (this.words[A] | 0)) % n;
        return s ? -w : w;
      }, a.prototype.modn = function(n) {
        return this.modrn(n);
      }, a.prototype.idivn = function(n) {
        var s = n < 0;
        s && (n = -n), i(n <= 67108863);
        for (var d = 0, w = this.length - 1; w >= 0; w--) {
          var A = (this.words[w] | 0) + d * 67108864;
          this.words[w] = A / n | 0, d = A % n;
        }
        return this._strip(), s ? this.ineg() : this;
      }, a.prototype.divn = function(n) {
        return this.clone().idivn(n);
      }, a.prototype.egcd = function(n) {
        i(n.negative === 0), i(!n.isZero());
        var s = this, d = n.clone();
        s.negative !== 0 ? s = s.umod(n) : s = s.clone();
        for (var w = new a(1), A = new a(0), k = new a(0), l = new a(1), y = 0; s.isEven() && d.isEven(); )
          s.iushrn(1), d.iushrn(1), ++y;
        for (var v = d.clone(), P = s.clone(); !s.isZero(); ) {
          for (var J = 0, Y = 1; (s.words[0] & Y) === 0 && J < 26; ++J, Y <<= 1) ;
          if (J > 0)
            for (s.iushrn(J); J-- > 0; )
              (w.isOdd() || A.isOdd()) && (w.iadd(v), A.isub(P)), w.iushrn(1), A.iushrn(1);
          for (var Q = 0, se = 1; (d.words[0] & se) === 0 && Q < 26; ++Q, se <<= 1) ;
          if (Q > 0)
            for (d.iushrn(Q); Q-- > 0; )
              (k.isOdd() || l.isOdd()) && (k.iadd(v), l.isub(P)), k.iushrn(1), l.iushrn(1);
          s.cmp(d) >= 0 ? (s.isub(d), w.isub(k), A.isub(l)) : (d.isub(s), k.isub(w), l.isub(A));
        }
        return {
          a: k,
          b: l,
          gcd: d.iushln(y)
        };
      }, a.prototype._invmp = function(n) {
        i(n.negative === 0), i(!n.isZero());
        var s = this, d = n.clone();
        s.negative !== 0 ? s = s.umod(n) : s = s.clone();
        for (var w = new a(1), A = new a(0), k = d.clone(); s.cmpn(1) > 0 && d.cmpn(1) > 0; ) {
          for (var l = 0, y = 1; (s.words[0] & y) === 0 && l < 26; ++l, y <<= 1) ;
          if (l > 0)
            for (s.iushrn(l); l-- > 0; )
              w.isOdd() && w.iadd(k), w.iushrn(1);
          for (var v = 0, P = 1; (d.words[0] & P) === 0 && v < 26; ++v, P <<= 1) ;
          if (v > 0)
            for (d.iushrn(v); v-- > 0; )
              A.isOdd() && A.iadd(k), A.iushrn(1);
          s.cmp(d) >= 0 ? (s.isub(d), w.isub(A)) : (d.isub(s), A.isub(w));
        }
        var J;
        return s.cmpn(1) === 0 ? J = w : J = A, J.cmpn(0) < 0 && J.iadd(n), J;
      }, a.prototype.gcd = function(n) {
        if (this.isZero()) return n.abs();
        if (n.isZero()) return this.abs();
        var s = this.clone(), d = n.clone();
        s.negative = 0, d.negative = 0;
        for (var w = 0; s.isEven() && d.isEven(); w++)
          s.iushrn(1), d.iushrn(1);
        do {
          for (; s.isEven(); )
            s.iushrn(1);
          for (; d.isEven(); )
            d.iushrn(1);
          var A = s.cmp(d);
          if (A < 0) {
            var k = s;
            s = d, d = k;
          } else if (A === 0 || d.cmpn(1) === 0)
            break;
          s.isub(d);
        } while (!0);
        return d.iushln(w);
      }, a.prototype.invm = function(n) {
        return this.egcd(n).a.umod(n);
      }, a.prototype.isEven = function() {
        return (this.words[0] & 1) === 0;
      }, a.prototype.isOdd = function() {
        return (this.words[0] & 1) === 1;
      }, a.prototype.andln = function(n) {
        return this.words[0] & n;
      }, a.prototype.bincn = function(n) {
        i(typeof n == "number");
        var s = n % 26, d = (n - s) / 26, w = 1 << s;
        if (this.length <= d)
          return this._expand(d + 1), this.words[d] |= w, this;
        for (var A = w, k = d; A !== 0 && k < this.length; k++) {
          var l = this.words[k] | 0;
          l += A, A = l >>> 26, l &= 67108863, this.words[k] = l;
        }
        return A !== 0 && (this.words[k] = A, this.length++), this;
      }, a.prototype.isZero = function() {
        return this.length === 1 && this.words[0] === 0;
      }, a.prototype.cmpn = function(n) {
        var s = n < 0;
        if (this.negative !== 0 && !s) return -1;
        if (this.negative === 0 && s) return 1;
        this._strip();
        var d;
        if (this.length > 1)
          d = 1;
        else {
          s && (n = -n), i(n <= 67108863, "Number is too big");
          var w = this.words[0] | 0;
          d = w === n ? 0 : w < n ? -1 : 1;
        }
        return this.negative !== 0 ? -d | 0 : d;
      }, a.prototype.cmp = function(n) {
        if (this.negative !== 0 && n.negative === 0) return -1;
        if (this.negative === 0 && n.negative !== 0) return 1;
        var s = this.ucmp(n);
        return this.negative !== 0 ? -s | 0 : s;
      }, a.prototype.ucmp = function(n) {
        if (this.length > n.length) return 1;
        if (this.length < n.length) return -1;
        for (var s = 0, d = this.length - 1; d >= 0; d--) {
          var w = this.words[d] | 0, A = n.words[d] | 0;
          if (w !== A) {
            w < A ? s = -1 : w > A && (s = 1);
            break;
          }
        }
        return s;
      }, a.prototype.gtn = function(n) {
        return this.cmpn(n) === 1;
      }, a.prototype.gt = function(n) {
        return this.cmp(n) === 1;
      }, a.prototype.gten = function(n) {
        return this.cmpn(n) >= 0;
      }, a.prototype.gte = function(n) {
        return this.cmp(n) >= 0;
      }, a.prototype.ltn = function(n) {
        return this.cmpn(n) === -1;
      }, a.prototype.lt = function(n) {
        return this.cmp(n) === -1;
      }, a.prototype.lten = function(n) {
        return this.cmpn(n) <= 0;
      }, a.prototype.lte = function(n) {
        return this.cmp(n) <= 0;
      }, a.prototype.eqn = function(n) {
        return this.cmpn(n) === 0;
      }, a.prototype.eq = function(n) {
        return this.cmp(n) === 0;
      }, a.red = function(n) {
        return new z(n);
      }, a.prototype.toRed = function(n) {
        return i(!this.red, "Already a number in reduction context"), i(this.negative === 0, "red works only with positives"), n.convertTo(this)._forceRed(n);
      }, a.prototype.fromRed = function() {
        return i(this.red, "fromRed works only with numbers in reduction context"), this.red.convertFrom(this);
      }, a.prototype._forceRed = function(n) {
        return this.red = n, this;
      }, a.prototype.forceRed = function(n) {
        return i(!this.red, "Already a number in reduction context"), this._forceRed(n);
      }, a.prototype.redAdd = function(n) {
        return i(this.red, "redAdd works only with red numbers"), this.red.add(this, n);
      }, a.prototype.redIAdd = function(n) {
        return i(this.red, "redIAdd works only with red numbers"), this.red.iadd(this, n);
      }, a.prototype.redSub = function(n) {
        return i(this.red, "redSub works only with red numbers"), this.red.sub(this, n);
      }, a.prototype.redISub = function(n) {
        return i(this.red, "redISub works only with red numbers"), this.red.isub(this, n);
      }, a.prototype.redShl = function(n) {
        return i(this.red, "redShl works only with red numbers"), this.red.shl(this, n);
      }, a.prototype.redMul = function(n) {
        return i(this.red, "redMul works only with red numbers"), this.red._verify2(this, n), this.red.mul(this, n);
      }, a.prototype.redIMul = function(n) {
        return i(this.red, "redMul works only with red numbers"), this.red._verify2(this, n), this.red.imul(this, n);
      }, a.prototype.redSqr = function() {
        return i(this.red, "redSqr works only with red numbers"), this.red._verify1(this), this.red.sqr(this);
      }, a.prototype.redISqr = function() {
        return i(this.red, "redISqr works only with red numbers"), this.red._verify1(this), this.red.isqr(this);
      }, a.prototype.redSqrt = function() {
        return i(this.red, "redSqrt works only with red numbers"), this.red._verify1(this), this.red.sqrt(this);
      }, a.prototype.redInvm = function() {
        return i(this.red, "redInvm works only with red numbers"), this.red._verify1(this), this.red.invm(this);
      }, a.prototype.redNeg = function() {
        return i(this.red, "redNeg works only with red numbers"), this.red._verify1(this), this.red.neg(this);
      }, a.prototype.redPow = function(n) {
        return i(this.red && !n.red, "redPow(normalNum)"), this.red._verify1(this), this.red.pow(this, n);
      };
      var C = {
        k256: null,
        p224: null,
        p192: null,
        p25519: null
      };
      function q(u, n) {
        this.name = u, this.p = new a(n, 16), this.n = this.p.bitLength(), this.k = new a(1).iushln(this.n).isub(this.p), this.tmp = this._tmp();
      }
      q.prototype._tmp = function() {
        var n = new a(null);
        return n.words = new Array(Math.ceil(this.n / 13)), n;
      }, q.prototype.ireduce = function(n) {
        var s = n, d;
        do
          this.split(s, this.tmp), s = this.imulK(s), s = s.iadd(this.tmp), d = s.bitLength();
        while (d > this.n);
        var w = d < this.n ? -1 : s.ucmp(this.p);
        return w === 0 ? (s.words[0] = 0, s.length = 1) : w > 0 ? s.isub(this.p) : s.strip !== void 0 ? s.strip() : s._strip(), s;
      }, q.prototype.split = function(n, s) {
        n.iushrn(this.n, 0, s);
      }, q.prototype.imulK = function(n) {
        return n.imul(this.k);
      };
      function V() {
        q.call(
          this,
          "k256",
          "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f"
        );
      }
      o(V, q), V.prototype.split = function(n, s) {
        for (var d = 4194303, w = Math.min(n.length, 9), A = 0; A < w; A++)
          s.words[A] = n.words[A];
        if (s.length = w, n.length <= 9) {
          n.words[0] = 0, n.length = 1;
          return;
        }
        var k = n.words[9];
        for (s.words[s.length++] = k & d, A = 10; A < n.length; A++) {
          var l = n.words[A] | 0;
          n.words[A - 10] = (l & d) << 4 | k >>> 22, k = l;
        }
        k >>>= 22, n.words[A - 10] = k, k === 0 && n.length > 10 ? n.length -= 10 : n.length -= 9;
      }, V.prototype.imulK = function(n) {
        n.words[n.length] = 0, n.words[n.length + 1] = 0, n.length += 2;
        for (var s = 0, d = 0; d < n.length; d++) {
          var w = n.words[d] | 0;
          s += w * 977, n.words[d] = s & 67108863, s = w * 64 + (s / 67108864 | 0);
        }
        return n.words[n.length - 1] === 0 && (n.length--, n.words[n.length - 1] === 0 && n.length--), n;
      };
      function Z() {
        q.call(
          this,
          "p224",
          "ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001"
        );
      }
      o(Z, q);
      function K() {
        q.call(
          this,
          "p192",
          "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff"
        );
      }
      o(K, q);
      function G() {
        q.call(
          this,
          "25519",
          "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed"
        );
      }
      o(G, q), G.prototype.imulK = function(n) {
        for (var s = 0, d = 0; d < n.length; d++) {
          var w = (n.words[d] | 0) * 19 + s, A = w & 67108863;
          w >>>= 26, n.words[d] = A, s = w;
        }
        return s !== 0 && (n.words[n.length++] = s), n;
      }, a._prime = function(n) {
        if (C[n]) return C[n];
        var s;
        if (n === "k256")
          s = new V();
        else if (n === "p224")
          s = new Z();
        else if (n === "p192")
          s = new K();
        else if (n === "p25519")
          s = new G();
        else
          throw new Error("Unknown prime " + n);
        return C[n] = s, s;
      };
      function z(u) {
        if (typeof u == "string") {
          var n = a._prime(u);
          this.m = n.p, this.prime = n;
        } else
          i(u.gtn(1), "modulus must be greater than 1"), this.m = u, this.prime = null;
      }
      z.prototype._verify1 = function(n) {
        i(n.negative === 0, "red works only with positives"), i(n.red, "red works only with red numbers");
      }, z.prototype._verify2 = function(n, s) {
        i((n.negative | s.negative) === 0, "red works only with positives"), i(
          n.red && n.red === s.red,
          "red works only with red numbers"
        );
      }, z.prototype.imod = function(n) {
        return this.prime ? this.prime.ireduce(n)._forceRed(this) : (m(n, n.umod(this.m)._forceRed(this)), n);
      }, z.prototype.neg = function(n) {
        return n.isZero() ? n.clone() : this.m.sub(n)._forceRed(this);
      }, z.prototype.add = function(n, s) {
        this._verify2(n, s);
        var d = n.add(s);
        return d.cmp(this.m) >= 0 && d.isub(this.m), d._forceRed(this);
      }, z.prototype.iadd = function(n, s) {
        this._verify2(n, s);
        var d = n.iadd(s);
        return d.cmp(this.m) >= 0 && d.isub(this.m), d;
      }, z.prototype.sub = function(n, s) {
        this._verify2(n, s);
        var d = n.sub(s);
        return d.cmpn(0) < 0 && d.iadd(this.m), d._forceRed(this);
      }, z.prototype.isub = function(n, s) {
        this._verify2(n, s);
        var d = n.isub(s);
        return d.cmpn(0) < 0 && d.iadd(this.m), d;
      }, z.prototype.shl = function(n, s) {
        return this._verify1(n), this.imod(n.ushln(s));
      }, z.prototype.imul = function(n, s) {
        return this._verify2(n, s), this.imod(n.imul(s));
      }, z.prototype.mul = function(n, s) {
        return this._verify2(n, s), this.imod(n.mul(s));
      }, z.prototype.isqr = function(n) {
        return this.imul(n, n.clone());
      }, z.prototype.sqr = function(n) {
        return this.mul(n, n);
      }, z.prototype.sqrt = function(n) {
        if (n.isZero()) return n.clone();
        var s = this.m.andln(3);
        if (i(s % 2 === 1), s === 3) {
          var d = this.m.add(new a(1)).iushrn(2);
          return this.pow(n, d);
        }
        for (var w = this.m.subn(1), A = 0; !w.isZero() && w.andln(1) === 0; )
          A++, w.iushrn(1);
        i(!w.isZero());
        var k = new a(1).toRed(this), l = k.redNeg(), y = this.m.subn(1).iushrn(1), v = this.m.bitLength();
        for (v = new a(2 * v * v).toRed(this); this.pow(v, y).cmp(l) !== 0; )
          v.redIAdd(l);
        for (var P = this.pow(v, w), J = this.pow(n, w.addn(1).iushrn(1)), Y = this.pow(n, w), Q = A; Y.cmp(k) !== 0; ) {
          for (var se = Y, pe = 0; se.cmp(k) !== 0; pe++)
            se = se.redSqr();
          i(pe < Q);
          var ne = this.pow(P, new a(1).iushln(Q - pe - 1));
          J = J.redMul(ne), P = ne.redSqr(), Y = Y.redMul(P), Q = pe;
        }
        return J;
      }, z.prototype.invm = function(n) {
        var s = n._invmp(this.m);
        return s.negative !== 0 ? (s.negative = 0, this.imod(s).redNeg()) : this.imod(s);
      }, z.prototype.pow = function(n, s) {
        if (s.isZero()) return new a(1).toRed(this);
        if (s.cmpn(1) === 0) return n.clone();
        var d = 4, w = new Array(1 << d);
        w[0] = new a(1).toRed(this), w[1] = n;
        for (var A = 2; A < w.length; A++)
          w[A] = this.mul(w[A - 1], n);
        var k = w[0], l = 0, y = 0, v = s.bitLength() % 26;
        for (v === 0 && (v = 26), A = s.length - 1; A >= 0; A--) {
          for (var P = s.words[A], J = v - 1; J >= 0; J--) {
            var Y = P >> J & 1;
            if (k !== w[0] && (k = this.sqr(k)), Y === 0 && l === 0) {
              y = 0;
              continue;
            }
            l <<= 1, l |= Y, y++, !(y !== d && (A !== 0 || J !== 0)) && (k = this.mul(k, w[l]), y = 0, l = 0);
          }
          v = 26;
        }
        return k;
      }, z.prototype.convertTo = function(n) {
        var s = n.umod(this.m);
        return s === n ? s.clone() : s;
      }, z.prototype.convertFrom = function(n) {
        var s = n.clone();
        return s.red = null, s;
      }, a.mont = function(n) {
        return new f(n);
      };
      function f(u) {
        z.call(this, u), this.shift = this.m.bitLength(), this.shift % 26 !== 0 && (this.shift += 26 - this.shift % 26), this.r = new a(1).iushln(this.shift), this.r2 = this.imod(this.r.sqr()), this.rinv = this.r._invmp(this.m), this.minv = this.rinv.mul(this.r).isubn(1).div(this.m), this.minv = this.minv.umod(this.r), this.minv = this.r.sub(this.minv);
      }
      o(f, z), f.prototype.convertTo = function(n) {
        return this.imod(n.ushln(this.shift));
      }, f.prototype.convertFrom = function(n) {
        var s = this.imod(n.mul(this.rinv));
        return s.red = null, s;
      }, f.prototype.imul = function(n, s) {
        if (n.isZero() || s.isZero())
          return n.words[0] = 0, n.length = 1, n;
        var d = n.imul(s), w = d.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m), A = d.isub(w).iushrn(this.shift), k = A;
        return A.cmp(this.m) >= 0 ? k = A.isub(this.m) : A.cmpn(0) < 0 && (k = A.iadd(this.m)), k._forceRed(this);
      }, f.prototype.mul = function(n, s) {
        if (n.isZero() || s.isZero()) return new a(0)._forceRed(this);
        var d = n.mul(s), w = d.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m), A = d.isub(w).iushrn(this.shift), k = A;
        return A.cmp(this.m) >= 0 ? k = A.isub(this.m) : A.cmpn(0) < 0 && (k = A.iadd(this.m)), k._forceRed(this);
      }, f.prototype.invm = function(n) {
        var s = this.imod(n._invmp(this.m).mul(this.r2));
        return s._forceRed(this);
      };
    })(r, ec);
  })(Mi)), Mi.exports;
}
var rc = tc();
const ic = /* @__PURE__ */ Fi(rc);
function Ti(r, e) {
  var t;
  e === void 0 && (e = "0");
  var i = 0, o = -1;
  r[0] == "-" && (r = r.substring(1), Ra(r) || (i++, o = 1, r.length)), e[0] == "-" && (e = e.substring(1), Ra(e) || (i++, o = 2, e.length)), r = It(r), e = It(e), t = nn(It(r), It(e)), r = t[0], e = t[1], i == 1 && (o === 1 ? r = Wi(r) : o === 2 && (e = Wi(e)));
  var a = xs(r, e);
  return i ? i == 2 ? "-" + It(a) : r.length < a.length ? It(a.substring(1)) : "-" + It(Wi(a)) : It(a);
}
function Wi(r) {
  if (Ra(r))
    return r;
  for (var e = "", t = r.length, i = r.split(".")[1], o = i ? i.length : 0, a = 0; a < t; a++)
    r[a] >= "0" && r[a] <= "9" ? e += 9 - parseInt(r[a]) : e += r[a];
  var p = o > 0 ? "0." + new Array(o).join("0") + "1" : "1";
  return xs(e, p);
}
function It(r) {
  var e = r.split(".");
  for (e[0] || (e[0] = "0"); e[0][0] == "0" && e[0].length > 1; )
    e[0] = e[0].substring(1);
  return e[0] + (e[1] ? "." + e[1] : "");
}
function nn(r, e) {
  var t = r.split("."), i = e.split("."), o = t[0].length, a = i[0].length;
  return o > a ? i[0] = new Array(Math.abs(o - a) + 1).join("0") + (i[0] ? i[0] : "") : t[0] = new Array(Math.abs(o - a) + 1).join("0") + (t[0] ? t[0] : ""), o = t[1] ? t[1].length : 0, a = i[1] ? i[1].length : 0, (o || a) && (o > a ? i[1] = (i[1] ? i[1] : "") + new Array(Math.abs(o - a) + 1).join("0") : t[1] = (t[1] ? t[1] : "") + new Array(Math.abs(o - a) + 1).join("0")), r = t[0] + (t[1] ? "." + t[1] : ""), e = i[0] + (i[1] ? "." + i[1] : ""), [r, e];
}
function xs(r, e) {
  var t;
  t = nn(r, e), r = t[0], e = t[1];
  for (var i = "", o = 0, a = r.length - 1; a >= 0; a--) {
    if (r[a] === ".") {
      i = "." + i;
      continue;
    }
    var p = parseInt(r[a]) + parseInt(e[a]) + o;
    i = p % 10 + i, o = Math.floor(p / 10);
  }
  return o ? o.toString() + i : i;
}
function Ra(r) {
  return /^0[0]*[.]{0,1}[0]*$/.test(r);
}
function Vn(r) {
  return (typeof r == "number" || typeof r == "bigint") && (r = r.toString()), r[0] == "-" ? r.substring(1) : r;
}
var pt;
(function(r) {
  r[r.CEILING = 0] = "CEILING", r[r.DOWN = 1] = "DOWN", r[r.FLOOR = 2] = "FLOOR", r[r.HALF_DOWN = 3] = "HALF_DOWN", r[r.HALF_EVEN = 4] = "HALF_EVEN", r[r.HALF_UP = 5] = "HALF_UP", r[r.UNNECESSARY = 6] = "UNNECESSARY", r[r.UP = 7] = "UP";
})(pt || (pt = {}));
function ni(r, e, t) {
  if (e === void 0 && (e = 0), t === void 0 && (t = pt.HALF_EVEN), t === pt.UNNECESSARY)
    throw new Error("UNNECESSARY Rounding Mode has not yet been implemented");
  (typeof r == "number" || typeof r == "bigint") && (r = r.toString());
  var i = !1;
  r[0] === "-" && (i = !0, r = r.substring(1));
  var o = r.split("."), a = o[0], p = o[1];
  if (e < 0) {
    if (e = -e, a.length <= e)
      return "0";
    var c = a.substr(0, a.length - e);
    return r = c + "." + a.substr(a.length - e) + p, c = ni(r, 0, t), (i ? "-" : "") + c + new Array(e + 1).join("0");
  }
  if (e == 0)
    return a.length, Gn(o[1], a, i, t) && (a = Ji(a)), (i && parseInt(a) ? "-" : "") + a;
  if (o[1]) {
    if (o[1].length < e)
      return (i ? "-" : "") + a + "." + o[1] + new Array(e - o[1].length + 1).join("0");
  } else return (i ? "-" : "") + a + "." + new Array(e + 1).join("0");
  p = o[1].substring(0, e);
  var g = o[1].substring(e);
  return g && Gn(g, p, i, t) && (p = Ji(p), p.length > e) ? (i ? "-" : "") + Ji(a, parseInt(p[0])) + "." + p.substring(1) : (i && (parseInt(a) || parseInt(p)) ? "-" : "") + a + "." + p;
}
function Gn(r, e, t, i) {
  if (!r || r === new Array(r.length + 1).join("0") || i === pt.DOWN || !t && i === pt.FLOOR || t && i === pt.CEILING)
    return !1;
  if (i === pt.UP || t && i === pt.FLOOR || !t && i === pt.CEILING)
    return !0;
  var o = "5" + new Array(r.length).join("0");
  if (r > o)
    return !0;
  if (r < o)
    return !1;
  switch (i) {
    case pt.HALF_DOWN:
      return !1;
    case pt.HALF_UP:
      return !0;
    case pt.HALF_EVEN:
    default:
      return parseInt(e[e.length - 1]) % 2 == 1;
  }
}
function Ji(r, e) {
  e === void 0 && (e = 0), e || (e = 1), typeof r == "number" && r.toString();
  for (var t = r.length - 1, i = "", o = t; o >= 0; o--) {
    var a = parseInt(r[o]) + e;
    a == 10 ? (e = 1, a = 0) : e = 0, i += a;
  }
  return e && (i += e), i.split("").reverse().join("");
}
function dr(r) {
  var e = r[0] === "-";
  for (e && (r = r.substr(1)); r[0] == "0"; )
    r = r.substr(1);
  if (r.indexOf(".") != -1)
    for (; r[r.length - 1] == "0"; )
      r = r.substr(0, r.length - 1);
  return r == "" || r == "." ? r = "0" : r[r.length - 1] == "." && (r = r.substr(0, r.length - 1)), r[0] == "." && (r = "0" + r), e && r != "0" && (r = "-" + r), r;
}
function La(r, e) {
  r = r.toString(), e = e.toString();
  var t = 0;
  r[0] == "-" && (t++, r = r.substr(1)), e[0] == "-" && (t++, e = e.substr(1)), r = dr(r), e = dr(e);
  var i = 0, o = 0;
  r.indexOf(".") != -1 && (i = r.length - r.indexOf(".") - 1), e.indexOf(".") != -1 && (o = e.length - e.indexOf(".") - 1);
  var a = i + o;
  if (r = dr(r.replace(".", "")), e = dr(e.replace(".", "")), r.length < e.length) {
    var p = r;
    r = e, e = p;
  }
  if (e == "0")
    return "0";
  for (var c = e.length, g = 0, h = [], m = c - 1, S = "", M = 0; M < c; M++)
    h[M] = r.length - 1;
  for (var M = 0; M < 2 * r.length; M++) {
    for (var I = 0, _ = e.length - 1; _ >= m && _ >= 0; _--)
      h[_] > -1 && h[_] < r.length && (I += parseInt(r[h[_]--]) * parseInt(e[_]));
    I += g, g = Math.floor(I / 10), S = I % 10 + S, m--;
  }
  return S = dr(ac(S, a)), t == 1 && (S = "-" + S), S;
}
function ac(r, e) {
  return e == 0 ? r : (r = e >= r.length ? new Array(e - r.length + 1).join("0") + r : r, r.substr(0, r.length - e) + "." + r.substr(r.length - e, e));
}
function Ua(r, e, t, i) {
  if (t === void 0 && (t = 8), i === void 0 && (i = pt.HALF_EVEN), e == 0)
    throw new Error("Cannot divide by 0");
  if (r = r.toString(), e = e.toString(), r = r.replace(/(\.\d*?[1-9])0+$/g, "$1").replace(/\.0+$/, ""), e = e.replace(/(\.\d*?[1-9])0+$/g, "$1").replace(/\.0+$/, ""), r == 0)
    return "0";
  var o = 0;
  e[0] == "-" && (e = e.substring(1), o++), r[0] == "-" && (r = r.substring(1), o++);
  var a = e.indexOf(".") > 0 ? e.length - e.indexOf(".") - 1 : -1;
  if (e = It(e.replace(".", "")), a >= 0) {
    var p = r.indexOf(".") > 0 ? r.length - r.indexOf(".") - 1 : -1;
    if (p == -1)
      r = It(r + new Array(a + 1).join("0"));
    else if (a > p)
      r = r.replace(".", ""), r = It(r + new Array(a - p + 1).join("0"));
    else if (a < p) {
      r = r.replace(".", "");
      var c = r.length - p + a;
      r = It(r.substring(0, c) + "." + r.substring(c));
    } else a == p && (r = It(r.replace(".", "")));
  }
  var g = 0, h = e.length, m = "", S = r.indexOf(".") > -1 && r.indexOf(".") < h ? r.substring(0, h + 1) : r.substring(0, h);
  if (r = r.indexOf(".") > -1 && r.indexOf(".") < h ? r.substring(h + 1) : r.substring(h), S.indexOf(".") > -1) {
    var M = S.length - S.indexOf(".") - 1;
    S = S.replace(".", ""), h > S.length && (M += h - S.length, S = S + new Array(h - S.length + 1).join("0")), g = M, m = "0." + new Array(M).join("0");
  }
  for (t = t + 2; g <= t; ) {
    for (var I = 0; parseInt(S) >= parseInt(e); )
      S = Ti(S, "-" + e), I++;
    m += I, r ? (r[0] == "." && (m += ".", g++, r = r.substring(1)), S = S + r.substring(0, 1), r = r.substring(1)) : (g || (m += "."), g++, S = S + "0");
  }
  return (o == 1 ? "-" : "") + It(ni(m, t - 2, i));
}
function ja(r, e) {
  return r = r.toString(), e = e.toString(), e = Ka(e), Ti(r, e);
}
function Ka(r) {
  return r[0] == "-" ? r = r.substr(1) : r = "-" + r, r;
}
function Wn(r, e) {
  if (e == 0)
    throw new Error("Cannot divide by 0");
  r = r.toString(), e = e.toString(), Jn(r), Jn(e);
  var t = "";
  r[0] == "-" && (t = "-", r = r.substr(1)), e[0] == "-" && (e = e.substr(1));
  var i = ja(r, La(e, ni(Ua(r, e), 0, pt.FLOOR)));
  return t + i;
}
function Jn(r) {
  if (r.indexOf(".") != -1)
    throw new Error("Modulus of non-integers not supported");
}
function Yn(r, e) {
  var t, i, o = !1;
  if (t = [r, e].map(function(p) {
    return dr(p);
  }), r = t[0], e = t[1], r[0] == "-" && e[0] != "-")
    return -1;
  if (r[0] != "-" && e[0] == "-")
    return 1;
  if (r[0] == "-" && e[0] == "-" && (r = r.substr(1), e = e.substr(1), o = !0), i = nn(r, e), r = i[0], e = i[1], r.localeCompare(e) == 0)
    return 0;
  for (var a = 0; a < r.length; a++)
    if (r[a] != e[a])
      return r[a] > e[a] ? o ? -1 : 1 : o ? 1 : -1;
  return 0;
}
var Pt = (
  /** @class */
  (function() {
    function r(e) {
      e === void 0 && (e = "0"), this.value = r.validate(e);
    }
    return r.validate = function(e) {
      if (e) {
        if (e = e.toString(), isNaN(e))
          throw Error("Parameter is not a number: " + e);
        e[0] == "+" && (e = e.substring(1));
      } else
        e = "0";
      if (e.startsWith(".") ? e = "0" + e : e.startsWith("-.") && (e = "-0" + e.substr(1)), /e/i.test(e)) {
        var t = e.split(/[eE]/), i = t[0], o = t[1];
        i = It(i);
        var a = "";
        i[0] == "-" && (a = "-", i = i.substring(1)), i.indexOf(".") >= 0 ? (o = parseInt(o) + i.indexOf("."), i = i.replace(".", "")) : o = parseInt(o) + i.length, i.length < o ? e = a + i + new Array(o - i.length + 1).join("0") : i.length >= o && o > 0 ? e = a + It(i.substring(0, o)) + (i.length > o ? "." + i.substring(o) : "") : e = a + "0." + new Array(-o + 1).join("0") + i;
      }
      return e;
    }, r.prototype.getValue = function() {
      return this.value;
    }, r.prototype.setValue = function(e) {
      this.value = r.validate(e);
    }, r.getPrettyValue = function(e, t, i) {
      t === void 0 && (t = 3), i === void 0 && (i = ","), e = r.validate(e);
      var o = e.charAt(0) == "-";
      o && (e = e.substring(1));
      var a = e.indexOf(".");
      a = a > 0 ? a : e.length;
      for (var p = "", c = a; c > 0; )
        c < t ? (t = c, c = 0) : c -= t, p = e.substring(c, c + t) + (c < a - t && c >= 0 ? i : "") + p;
      return (o ? "-" : "") + p + e.substring(a);
    }, r.prototype.getPrettyValue = function(e, t) {
      return e === void 0 && (e = 3), t === void 0 && (t = ","), r.getPrettyValue(this.value, e, t);
    }, r.round = function(e, t, i) {
      if (t === void 0 && (t = 0), i === void 0 && (i = pt.HALF_EVEN), e = r.validate(e), isNaN(t))
        throw Error("Precision is not a number: " + t);
      return ni(e, t, i);
    }, r.prototype.round = function(e, t) {
      if (e === void 0 && (e = 0), t === void 0 && (t = pt.HALF_EVEN), isNaN(e))
        throw Error("Precision is not a number: " + e);
      return new r(ni(this.value, e, t));
    }, r.abs = function(e) {
      return e = r.validate(e), Vn(e);
    }, r.prototype.abs = function() {
      return new r(Vn(this.value));
    }, r.floor = function(e) {
      return e = r.validate(e), e.indexOf(".") === -1 ? e : r.round(e, 0, pt.FLOOR);
    }, r.prototype.floor = function() {
      return this.value.indexOf(".") === -1 ? new r(this.value) : new r(this.value).round(0, pt.FLOOR);
    }, r.ceil = function(e) {
      return e = r.validate(e), e.indexOf(".") === -1 ? e : r.round(e, 0, pt.CEILING);
    }, r.prototype.ceil = function() {
      return this.value.indexOf(".") === -1 ? new r(this.value) : new r(this.value).round(0, pt.CEILING);
    }, r.add = function(e, t) {
      return e = r.validate(e), t = r.validate(t), Ti(e, t);
    }, r.prototype.add = function(e) {
      return new r(Ti(this.value, e.getValue()));
    }, r.subtract = function(e, t) {
      return e = r.validate(e), t = r.validate(t), ja(e, t);
    }, r.prototype.subtract = function(e) {
      return new r(ja(this.value, e.getValue()));
    }, r.multiply = function(e, t) {
      return e = r.validate(e), t = r.validate(t), La(e, t);
    }, r.prototype.multiply = function(e) {
      return new r(La(this.value, e.getValue()));
    }, r.divide = function(e, t, i, o) {
      return e = r.validate(e), t = r.validate(t), Ua(e, t, i, o);
    }, r.prototype.divide = function(e, t, i) {
      return new r(Ua(this.value, e.getValue(), t, i));
    }, r.modulus = function(e, t) {
      return e = r.validate(e), t = r.validate(t), Wn(e, t);
    }, r.prototype.modulus = function(e) {
      return new r(Wn(this.value, e.getValue()));
    }, r.compareTo = function(e, t) {
      return e = r.validate(e), t = r.validate(t), Yn(e, t);
    }, r.prototype.compareTo = function(e) {
      return Yn(this.value, e.getValue());
    }, r.negate = function(e) {
      return e = r.validate(e), Ka(e);
    }, r.prototype.negate = function() {
      return new r(Ka(this.value));
    }, r.stripTrailingZero = function(e) {
      return e = r.validate(e), dr(e);
    }, r.prototype.stripTrailingZero = function() {
      return new r(dr(this.value));
    }, r.RoundingModes = pt, r;
  })()
), Yi = {};
const nc = "6.6.1", oc = {
  version: nc
};
var Xi = {}, Bi = { exports: {} }, sc = Bi.exports, Xn;
function nr() {
  return Xn || (Xn = 1, (function(r) {
    (function(e, t) {
      function i(z, f) {
        if (!z) throw new Error(f || "Assertion failed");
      }
      function o(z, f) {
        z.super_ = f;
        var u = function() {
        };
        u.prototype = f.prototype, z.prototype = new u(), z.prototype.constructor = z;
      }
      function a(z, f, u) {
        if (a.isBN(z))
          return z;
        this.negative = 0, this.words = null, this.length = 0, this.red = null, z !== null && ((f === "le" || f === "be") && (u = f, f = 10), this._init(z || 0, f || 10, u || "be"));
      }
      typeof e == "object" ? e.exports = a : t.BN = a, a.BN = a, a.wordSize = 26;
      var p;
      try {
        typeof window < "u" && typeof window.Buffer < "u" ? p = window.Buffer : p = an.Buffer;
      } catch {
      }
      a.isBN = function(f) {
        return f instanceof a ? !0 : f !== null && typeof f == "object" && f.constructor.wordSize === a.wordSize && Array.isArray(f.words);
      }, a.max = function(f, u) {
        return f.cmp(u) > 0 ? f : u;
      }, a.min = function(f, u) {
        return f.cmp(u) < 0 ? f : u;
      }, a.prototype._init = function(f, u, n) {
        if (typeof f == "number")
          return this._initNumber(f, u, n);
        if (typeof f == "object")
          return this._initArray(f, u, n);
        u === "hex" && (u = 16), i(u === (u | 0) && u >= 2 && u <= 36), f = f.toString().replace(/\s+/g, "");
        var s = 0;
        f[0] === "-" && (s++, this.negative = 1), s < f.length && (u === 16 ? this._parseHex(f, s, n) : (this._parseBase(f, u, s), n === "le" && this._initArray(this.toArray(), u, n)));
      }, a.prototype._initNumber = function(f, u, n) {
        f < 0 && (this.negative = 1, f = -f), f < 67108864 ? (this.words = [f & 67108863], this.length = 1) : f < 4503599627370496 ? (this.words = [
          f & 67108863,
          f / 67108864 & 67108863
        ], this.length = 2) : (i(f < 9007199254740992), this.words = [
          f & 67108863,
          f / 67108864 & 67108863,
          1
        ], this.length = 3), n === "le" && this._initArray(this.toArray(), u, n);
      }, a.prototype._initArray = function(f, u, n) {
        if (i(typeof f.length == "number"), f.length <= 0)
          return this.words = [0], this.length = 1, this;
        this.length = Math.ceil(f.length / 3), this.words = new Array(this.length);
        for (var s = 0; s < this.length; s++)
          this.words[s] = 0;
        var d, w, A = 0;
        if (n === "be")
          for (s = f.length - 1, d = 0; s >= 0; s -= 3)
            w = f[s] | f[s - 1] << 8 | f[s - 2] << 16, this.words[d] |= w << A & 67108863, this.words[d + 1] = w >>> 26 - A & 67108863, A += 24, A >= 26 && (A -= 26, d++);
        else if (n === "le")
          for (s = 0, d = 0; s < f.length; s += 3)
            w = f[s] | f[s + 1] << 8 | f[s + 2] << 16, this.words[d] |= w << A & 67108863, this.words[d + 1] = w >>> 26 - A & 67108863, A += 24, A >= 26 && (A -= 26, d++);
        return this.strip();
      };
      function c(z, f) {
        var u = z.charCodeAt(f);
        return u >= 65 && u <= 70 ? u - 55 : u >= 97 && u <= 102 ? u - 87 : u - 48 & 15;
      }
      function g(z, f, u) {
        var n = c(z, u);
        return u - 1 >= f && (n |= c(z, u - 1) << 4), n;
      }
      a.prototype._parseHex = function(f, u, n) {
        this.length = Math.ceil((f.length - u) / 6), this.words = new Array(this.length);
        for (var s = 0; s < this.length; s++)
          this.words[s] = 0;
        var d = 0, w = 0, A;
        if (n === "be")
          for (s = f.length - 1; s >= u; s -= 2)
            A = g(f, u, s) << d, this.words[w] |= A & 67108863, d >= 18 ? (d -= 18, w += 1, this.words[w] |= A >>> 26) : d += 8;
        else {
          var k = f.length - u;
          for (s = k % 2 === 0 ? u + 1 : u; s < f.length; s += 2)
            A = g(f, u, s) << d, this.words[w] |= A & 67108863, d >= 18 ? (d -= 18, w += 1, this.words[w] |= A >>> 26) : d += 8;
        }
        this.strip();
      };
      function h(z, f, u, n) {
        for (var s = 0, d = Math.min(z.length, u), w = f; w < d; w++) {
          var A = z.charCodeAt(w) - 48;
          s *= n, A >= 49 ? s += A - 49 + 10 : A >= 17 ? s += A - 17 + 10 : s += A;
        }
        return s;
      }
      a.prototype._parseBase = function(f, u, n) {
        this.words = [0], this.length = 1;
        for (var s = 0, d = 1; d <= 67108863; d *= u)
          s++;
        s--, d = d / u | 0;
        for (var w = f.length - n, A = w % s, k = Math.min(w, w - A) + n, l = 0, y = n; y < k; y += s)
          l = h(f, y, y + s, u), this.imuln(d), this.words[0] + l < 67108864 ? this.words[0] += l : this._iaddn(l);
        if (A !== 0) {
          var v = 1;
          for (l = h(f, y, f.length, u), y = 0; y < A; y++)
            v *= u;
          this.imuln(v), this.words[0] + l < 67108864 ? this.words[0] += l : this._iaddn(l);
        }
        this.strip();
      }, a.prototype.copy = function(f) {
        f.words = new Array(this.length);
        for (var u = 0; u < this.length; u++)
          f.words[u] = this.words[u];
        f.length = this.length, f.negative = this.negative, f.red = this.red;
      }, a.prototype.clone = function() {
        var f = new a(null);
        return this.copy(f), f;
      }, a.prototype._expand = function(f) {
        for (; this.length < f; )
          this.words[this.length++] = 0;
        return this;
      }, a.prototype.strip = function() {
        for (; this.length > 1 && this.words[this.length - 1] === 0; )
          this.length--;
        return this._normSign();
      }, a.prototype._normSign = function() {
        return this.length === 1 && this.words[0] === 0 && (this.negative = 0), this;
      }, a.prototype.inspect = function() {
        return (this.red ? "<BN-R: " : "<BN: ") + this.toString(16) + ">";
      };
      var m = [
        "",
        "0",
        "00",
        "000",
        "0000",
        "00000",
        "000000",
        "0000000",
        "00000000",
        "000000000",
        "0000000000",
        "00000000000",
        "000000000000",
        "0000000000000",
        "00000000000000",
        "000000000000000",
        "0000000000000000",
        "00000000000000000",
        "000000000000000000",
        "0000000000000000000",
        "00000000000000000000",
        "000000000000000000000",
        "0000000000000000000000",
        "00000000000000000000000",
        "000000000000000000000000",
        "0000000000000000000000000"
      ], S = [
        0,
        0,
        25,
        16,
        12,
        11,
        10,
        9,
        8,
        8,
        7,
        7,
        7,
        7,
        6,
        6,
        6,
        6,
        6,
        6,
        6,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5,
        5
      ], M = [
        0,
        0,
        33554432,
        43046721,
        16777216,
        48828125,
        60466176,
        40353607,
        16777216,
        43046721,
        1e7,
        19487171,
        35831808,
        62748517,
        7529536,
        11390625,
        16777216,
        24137569,
        34012224,
        47045881,
        64e6,
        4084101,
        5153632,
        6436343,
        7962624,
        9765625,
        11881376,
        14348907,
        17210368,
        20511149,
        243e5,
        28629151,
        33554432,
        39135393,
        45435424,
        52521875,
        60466176
      ];
      a.prototype.toString = function(f, u) {
        f = f || 10, u = u | 0 || 1;
        var n;
        if (f === 16 || f === "hex") {
          n = "";
          for (var s = 0, d = 0, w = 0; w < this.length; w++) {
            var A = this.words[w], k = ((A << s | d) & 16777215).toString(16);
            d = A >>> 24 - s & 16777215, s += 2, s >= 26 && (s -= 26, w--), d !== 0 || w !== this.length - 1 ? n = m[6 - k.length] + k + n : n = k + n;
          }
          for (d !== 0 && (n = d.toString(16) + n); n.length % u !== 0; )
            n = "0" + n;
          return this.negative !== 0 && (n = "-" + n), n;
        }
        if (f === (f | 0) && f >= 2 && f <= 36) {
          var l = S[f], y = M[f];
          n = "";
          var v = this.clone();
          for (v.negative = 0; !v.isZero(); ) {
            var P = v.modn(y).toString(f);
            v = v.idivn(y), v.isZero() ? n = P + n : n = m[l - P.length] + P + n;
          }
          for (this.isZero() && (n = "0" + n); n.length % u !== 0; )
            n = "0" + n;
          return this.negative !== 0 && (n = "-" + n), n;
        }
        i(!1, "Base should be between 2 and 36");
      }, a.prototype.toNumber = function() {
        var f = this.words[0];
        return this.length === 2 ? f += this.words[1] * 67108864 : this.length === 3 && this.words[2] === 1 ? f += 4503599627370496 + this.words[1] * 67108864 : this.length > 2 && i(!1, "Number can only safely store up to 53 bits"), this.negative !== 0 ? -f : f;
      }, a.prototype.toJSON = function() {
        return this.toString(16);
      }, a.prototype.toBuffer = function(f, u) {
        return i(typeof p < "u"), this.toArrayLike(p, f, u);
      }, a.prototype.toArray = function(f, u) {
        return this.toArrayLike(Array, f, u);
      }, a.prototype.toArrayLike = function(f, u, n) {
        var s = this.byteLength(), d = n || Math.max(1, s);
        i(s <= d, "byte array longer than desired length"), i(d > 0, "Requested array length <= 0"), this.strip();
        var w = u === "le", A = new f(d), k, l, y = this.clone();
        if (w) {
          for (l = 0; !y.isZero(); l++)
            k = y.andln(255), y.iushrn(8), A[l] = k;
          for (; l < d; l++)
            A[l] = 0;
        } else {
          for (l = 0; l < d - s; l++)
            A[l] = 0;
          for (l = 0; !y.isZero(); l++)
            k = y.andln(255), y.iushrn(8), A[d - l - 1] = k;
        }
        return A;
      }, Math.clz32 ? a.prototype._countBits = function(f) {
        return 32 - Math.clz32(f);
      } : a.prototype._countBits = function(f) {
        var u = f, n = 0;
        return u >= 4096 && (n += 13, u >>>= 13), u >= 64 && (n += 7, u >>>= 7), u >= 8 && (n += 4, u >>>= 4), u >= 2 && (n += 2, u >>>= 2), n + u;
      }, a.prototype._zeroBits = function(f) {
        if (f === 0) return 26;
        var u = f, n = 0;
        return (u & 8191) === 0 && (n += 13, u >>>= 13), (u & 127) === 0 && (n += 7, u >>>= 7), (u & 15) === 0 && (n += 4, u >>>= 4), (u & 3) === 0 && (n += 2, u >>>= 2), (u & 1) === 0 && n++, n;
      }, a.prototype.bitLength = function() {
        var f = this.words[this.length - 1], u = this._countBits(f);
        return (this.length - 1) * 26 + u;
      };
      function I(z) {
        for (var f = new Array(z.bitLength()), u = 0; u < f.length; u++) {
          var n = u / 26 | 0, s = u % 26;
          f[u] = (z.words[n] & 1 << s) >>> s;
        }
        return f;
      }
      a.prototype.zeroBits = function() {
        if (this.isZero()) return 0;
        for (var f = 0, u = 0; u < this.length; u++) {
          var n = this._zeroBits(this.words[u]);
          if (f += n, n !== 26) break;
        }
        return f;
      }, a.prototype.byteLength = function() {
        return Math.ceil(this.bitLength() / 8);
      }, a.prototype.toTwos = function(f) {
        return this.negative !== 0 ? this.abs().inotn(f).iaddn(1) : this.clone();
      }, a.prototype.fromTwos = function(f) {
        return this.testn(f - 1) ? this.notn(f).iaddn(1).ineg() : this.clone();
      }, a.prototype.isNeg = function() {
        return this.negative !== 0;
      }, a.prototype.neg = function() {
        return this.clone().ineg();
      }, a.prototype.ineg = function() {
        return this.isZero() || (this.negative ^= 1), this;
      }, a.prototype.iuor = function(f) {
        for (; this.length < f.length; )
          this.words[this.length++] = 0;
        for (var u = 0; u < f.length; u++)
          this.words[u] = this.words[u] | f.words[u];
        return this.strip();
      }, a.prototype.ior = function(f) {
        return i((this.negative | f.negative) === 0), this.iuor(f);
      }, a.prototype.or = function(f) {
        return this.length > f.length ? this.clone().ior(f) : f.clone().ior(this);
      }, a.prototype.uor = function(f) {
        return this.length > f.length ? this.clone().iuor(f) : f.clone().iuor(this);
      }, a.prototype.iuand = function(f) {
        var u;
        this.length > f.length ? u = f : u = this;
        for (var n = 0; n < u.length; n++)
          this.words[n] = this.words[n] & f.words[n];
        return this.length = u.length, this.strip();
      }, a.prototype.iand = function(f) {
        return i((this.negative | f.negative) === 0), this.iuand(f);
      }, a.prototype.and = function(f) {
        return this.length > f.length ? this.clone().iand(f) : f.clone().iand(this);
      }, a.prototype.uand = function(f) {
        return this.length > f.length ? this.clone().iuand(f) : f.clone().iuand(this);
      }, a.prototype.iuxor = function(f) {
        var u, n;
        this.length > f.length ? (u = this, n = f) : (u = f, n = this);
        for (var s = 0; s < n.length; s++)
          this.words[s] = u.words[s] ^ n.words[s];
        if (this !== u)
          for (; s < u.length; s++)
            this.words[s] = u.words[s];
        return this.length = u.length, this.strip();
      }, a.prototype.ixor = function(f) {
        return i((this.negative | f.negative) === 0), this.iuxor(f);
      }, a.prototype.xor = function(f) {
        return this.length > f.length ? this.clone().ixor(f) : f.clone().ixor(this);
      }, a.prototype.uxor = function(f) {
        return this.length > f.length ? this.clone().iuxor(f) : f.clone().iuxor(this);
      }, a.prototype.inotn = function(f) {
        i(typeof f == "number" && f >= 0);
        var u = Math.ceil(f / 26) | 0, n = f % 26;
        this._expand(u), n > 0 && u--;
        for (var s = 0; s < u; s++)
          this.words[s] = ~this.words[s] & 67108863;
        return n > 0 && (this.words[s] = ~this.words[s] & 67108863 >> 26 - n), this.strip();
      }, a.prototype.notn = function(f) {
        return this.clone().inotn(f);
      }, a.prototype.setn = function(f, u) {
        i(typeof f == "number" && f >= 0);
        var n = f / 26 | 0, s = f % 26;
        return this._expand(n + 1), u ? this.words[n] = this.words[n] | 1 << s : this.words[n] = this.words[n] & ~(1 << s), this.strip();
      }, a.prototype.iadd = function(f) {
        var u;
        if (this.negative !== 0 && f.negative === 0)
          return this.negative = 0, u = this.isub(f), this.negative ^= 1, this._normSign();
        if (this.negative === 0 && f.negative !== 0)
          return f.negative = 0, u = this.isub(f), f.negative = 1, u._normSign();
        var n, s;
        this.length > f.length ? (n = this, s = f) : (n = f, s = this);
        for (var d = 0, w = 0; w < s.length; w++)
          u = (n.words[w] | 0) + (s.words[w] | 0) + d, this.words[w] = u & 67108863, d = u >>> 26;
        for (; d !== 0 && w < n.length; w++)
          u = (n.words[w] | 0) + d, this.words[w] = u & 67108863, d = u >>> 26;
        if (this.length = n.length, d !== 0)
          this.words[this.length] = d, this.length++;
        else if (n !== this)
          for (; w < n.length; w++)
            this.words[w] = n.words[w];
        return this;
      }, a.prototype.add = function(f) {
        var u;
        return f.negative !== 0 && this.negative === 0 ? (f.negative = 0, u = this.sub(f), f.negative ^= 1, u) : f.negative === 0 && this.negative !== 0 ? (this.negative = 0, u = f.sub(this), this.negative = 1, u) : this.length > f.length ? this.clone().iadd(f) : f.clone().iadd(this);
      }, a.prototype.isub = function(f) {
        if (f.negative !== 0) {
          f.negative = 0;
          var u = this.iadd(f);
          return f.negative = 1, u._normSign();
        } else if (this.negative !== 0)
          return this.negative = 0, this.iadd(f), this.negative = 1, this._normSign();
        var n = this.cmp(f);
        if (n === 0)
          return this.negative = 0, this.length = 1, this.words[0] = 0, this;
        var s, d;
        n > 0 ? (s = this, d = f) : (s = f, d = this);
        for (var w = 0, A = 0; A < d.length; A++)
          u = (s.words[A] | 0) - (d.words[A] | 0) + w, w = u >> 26, this.words[A] = u & 67108863;
        for (; w !== 0 && A < s.length; A++)
          u = (s.words[A] | 0) + w, w = u >> 26, this.words[A] = u & 67108863;
        if (w === 0 && A < s.length && s !== this)
          for (; A < s.length; A++)
            this.words[A] = s.words[A];
        return this.length = Math.max(this.length, A), s !== this && (this.negative = 1), this.strip();
      }, a.prototype.sub = function(f) {
        return this.clone().isub(f);
      };
      function _(z, f, u) {
        u.negative = f.negative ^ z.negative;
        var n = z.length + f.length | 0;
        u.length = n, n = n - 1 | 0;
        var s = z.words[0] | 0, d = f.words[0] | 0, w = s * d, A = w & 67108863, k = w / 67108864 | 0;
        u.words[0] = A;
        for (var l = 1; l < n; l++) {
          for (var y = k >>> 26, v = k & 67108863, P = Math.min(l, f.length - 1), J = Math.max(0, l - z.length + 1); J <= P; J++) {
            var Y = l - J | 0;
            s = z.words[Y] | 0, d = f.words[J] | 0, w = s * d + v, y += w / 67108864 | 0, v = w & 67108863;
          }
          u.words[l] = v | 0, k = y | 0;
        }
        return k !== 0 ? u.words[l] = k | 0 : u.length--, u.strip();
      }
      var E = function(f, u, n) {
        var s = f.words, d = u.words, w = n.words, A = 0, k, l, y, v = s[0] | 0, P = v & 8191, J = v >>> 13, Y = s[1] | 0, Q = Y & 8191, se = Y >>> 13, pe = s[2] | 0, ne = pe & 8191, Ne = pe >>> 13, qe = s[3] | 0, he = qe & 8191, Ee = qe >>> 13, Ce = s[4] | 0, fe = Ce & 8191, Re = Ce >>> 13, Fe = s[5] | 0, me = Fe & 8191, He = Fe >>> 13, De = s[6] | 0, ce = De & 8191, Pe = De >>> 13, je = s[7] | 0, de = je & 8191, Te = je >>> 13, Ve = s[8] | 0, B = Ve & 8191, b = Ve >>> 13, x = s[9] | 0, T = x & 8191, L = x >>> 13, D = d[0] | 0, H = D & 8191, ae = D >>> 13, be = d[1] | 0, ie = be & 8191, ve = be >>> 13, ue = d[2] | 0, we = ue & 8191, $e = ue >>> 13, et = d[3] | 0, xe = et & 8191, tt = et >>> 13, rt = d[4] | 0, ke = rt & 8191, it = rt >>> 13, at = d[5] | 0, Se = at & 8191, nt = at >>> 13, ot = d[6] | 0, Ae = ot & 8191, st = ot >>> 13, ut = d[7] | 0, _e = ut & 8191, ft = ut >>> 13, ct = d[8] | 0, Me = ct & 8191, lt = ct >>> 13, ht = d[9] | 0, Be = ht & 8191, dt = ht >>> 13;
        n.negative = f.negative ^ u.negative, n.length = 19, k = Math.imul(P, H), l = Math.imul(P, ae), l = l + Math.imul(J, H) | 0, y = Math.imul(J, ae);
        var Ze = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Ze >>> 26) | 0, Ze &= 67108863, k = Math.imul(Q, H), l = Math.imul(Q, ae), l = l + Math.imul(se, H) | 0, y = Math.imul(se, ae), k = k + Math.imul(P, ie) | 0, l = l + Math.imul(P, ve) | 0, l = l + Math.imul(J, ie) | 0, y = y + Math.imul(J, ve) | 0;
        var Qe = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Qe >>> 26) | 0, Qe &= 67108863, k = Math.imul(ne, H), l = Math.imul(ne, ae), l = l + Math.imul(Ne, H) | 0, y = Math.imul(Ne, ae), k = k + Math.imul(Q, ie) | 0, l = l + Math.imul(Q, ve) | 0, l = l + Math.imul(se, ie) | 0, y = y + Math.imul(se, ve) | 0, k = k + Math.imul(P, we) | 0, l = l + Math.imul(P, $e) | 0, l = l + Math.imul(J, we) | 0, y = y + Math.imul(J, $e) | 0;
        var gr = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (gr >>> 26) | 0, gr &= 67108863, k = Math.imul(he, H), l = Math.imul(he, ae), l = l + Math.imul(Ee, H) | 0, y = Math.imul(Ee, ae), k = k + Math.imul(ne, ie) | 0, l = l + Math.imul(ne, ve) | 0, l = l + Math.imul(Ne, ie) | 0, y = y + Math.imul(Ne, ve) | 0, k = k + Math.imul(Q, we) | 0, l = l + Math.imul(Q, $e) | 0, l = l + Math.imul(se, we) | 0, y = y + Math.imul(se, $e) | 0, k = k + Math.imul(P, xe) | 0, l = l + Math.imul(P, tt) | 0, l = l + Math.imul(J, xe) | 0, y = y + Math.imul(J, tt) | 0;
        var yr = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (yr >>> 26) | 0, yr &= 67108863, k = Math.imul(fe, H), l = Math.imul(fe, ae), l = l + Math.imul(Re, H) | 0, y = Math.imul(Re, ae), k = k + Math.imul(he, ie) | 0, l = l + Math.imul(he, ve) | 0, l = l + Math.imul(Ee, ie) | 0, y = y + Math.imul(Ee, ve) | 0, k = k + Math.imul(ne, we) | 0, l = l + Math.imul(ne, $e) | 0, l = l + Math.imul(Ne, we) | 0, y = y + Math.imul(Ne, $e) | 0, k = k + Math.imul(Q, xe) | 0, l = l + Math.imul(Q, tt) | 0, l = l + Math.imul(se, xe) | 0, y = y + Math.imul(se, tt) | 0, k = k + Math.imul(P, ke) | 0, l = l + Math.imul(P, it) | 0, l = l + Math.imul(J, ke) | 0, y = y + Math.imul(J, it) | 0;
        var wr = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (wr >>> 26) | 0, wr &= 67108863, k = Math.imul(me, H), l = Math.imul(me, ae), l = l + Math.imul(He, H) | 0, y = Math.imul(He, ae), k = k + Math.imul(fe, ie) | 0, l = l + Math.imul(fe, ve) | 0, l = l + Math.imul(Re, ie) | 0, y = y + Math.imul(Re, ve) | 0, k = k + Math.imul(he, we) | 0, l = l + Math.imul(he, $e) | 0, l = l + Math.imul(Ee, we) | 0, y = y + Math.imul(Ee, $e) | 0, k = k + Math.imul(ne, xe) | 0, l = l + Math.imul(ne, tt) | 0, l = l + Math.imul(Ne, xe) | 0, y = y + Math.imul(Ne, tt) | 0, k = k + Math.imul(Q, ke) | 0, l = l + Math.imul(Q, it) | 0, l = l + Math.imul(se, ke) | 0, y = y + Math.imul(se, it) | 0, k = k + Math.imul(P, Se) | 0, l = l + Math.imul(P, nt) | 0, l = l + Math.imul(J, Se) | 0, y = y + Math.imul(J, nt) | 0;
        var xr = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (xr >>> 26) | 0, xr &= 67108863, k = Math.imul(ce, H), l = Math.imul(ce, ae), l = l + Math.imul(Pe, H) | 0, y = Math.imul(Pe, ae), k = k + Math.imul(me, ie) | 0, l = l + Math.imul(me, ve) | 0, l = l + Math.imul(He, ie) | 0, y = y + Math.imul(He, ve) | 0, k = k + Math.imul(fe, we) | 0, l = l + Math.imul(fe, $e) | 0, l = l + Math.imul(Re, we) | 0, y = y + Math.imul(Re, $e) | 0, k = k + Math.imul(he, xe) | 0, l = l + Math.imul(he, tt) | 0, l = l + Math.imul(Ee, xe) | 0, y = y + Math.imul(Ee, tt) | 0, k = k + Math.imul(ne, ke) | 0, l = l + Math.imul(ne, it) | 0, l = l + Math.imul(Ne, ke) | 0, y = y + Math.imul(Ne, it) | 0, k = k + Math.imul(Q, Se) | 0, l = l + Math.imul(Q, nt) | 0, l = l + Math.imul(se, Se) | 0, y = y + Math.imul(se, nt) | 0, k = k + Math.imul(P, Ae) | 0, l = l + Math.imul(P, st) | 0, l = l + Math.imul(J, Ae) | 0, y = y + Math.imul(J, st) | 0;
        var kr = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (kr >>> 26) | 0, kr &= 67108863, k = Math.imul(de, H), l = Math.imul(de, ae), l = l + Math.imul(Te, H) | 0, y = Math.imul(Te, ae), k = k + Math.imul(ce, ie) | 0, l = l + Math.imul(ce, ve) | 0, l = l + Math.imul(Pe, ie) | 0, y = y + Math.imul(Pe, ve) | 0, k = k + Math.imul(me, we) | 0, l = l + Math.imul(me, $e) | 0, l = l + Math.imul(He, we) | 0, y = y + Math.imul(He, $e) | 0, k = k + Math.imul(fe, xe) | 0, l = l + Math.imul(fe, tt) | 0, l = l + Math.imul(Re, xe) | 0, y = y + Math.imul(Re, tt) | 0, k = k + Math.imul(he, ke) | 0, l = l + Math.imul(he, it) | 0, l = l + Math.imul(Ee, ke) | 0, y = y + Math.imul(Ee, it) | 0, k = k + Math.imul(ne, Se) | 0, l = l + Math.imul(ne, nt) | 0, l = l + Math.imul(Ne, Se) | 0, y = y + Math.imul(Ne, nt) | 0, k = k + Math.imul(Q, Ae) | 0, l = l + Math.imul(Q, st) | 0, l = l + Math.imul(se, Ae) | 0, y = y + Math.imul(se, st) | 0, k = k + Math.imul(P, _e) | 0, l = l + Math.imul(P, ft) | 0, l = l + Math.imul(J, _e) | 0, y = y + Math.imul(J, ft) | 0;
        var Sr = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Sr >>> 26) | 0, Sr &= 67108863, k = Math.imul(B, H), l = Math.imul(B, ae), l = l + Math.imul(b, H) | 0, y = Math.imul(b, ae), k = k + Math.imul(de, ie) | 0, l = l + Math.imul(de, ve) | 0, l = l + Math.imul(Te, ie) | 0, y = y + Math.imul(Te, ve) | 0, k = k + Math.imul(ce, we) | 0, l = l + Math.imul(ce, $e) | 0, l = l + Math.imul(Pe, we) | 0, y = y + Math.imul(Pe, $e) | 0, k = k + Math.imul(me, xe) | 0, l = l + Math.imul(me, tt) | 0, l = l + Math.imul(He, xe) | 0, y = y + Math.imul(He, tt) | 0, k = k + Math.imul(fe, ke) | 0, l = l + Math.imul(fe, it) | 0, l = l + Math.imul(Re, ke) | 0, y = y + Math.imul(Re, it) | 0, k = k + Math.imul(he, Se) | 0, l = l + Math.imul(he, nt) | 0, l = l + Math.imul(Ee, Se) | 0, y = y + Math.imul(Ee, nt) | 0, k = k + Math.imul(ne, Ae) | 0, l = l + Math.imul(ne, st) | 0, l = l + Math.imul(Ne, Ae) | 0, y = y + Math.imul(Ne, st) | 0, k = k + Math.imul(Q, _e) | 0, l = l + Math.imul(Q, ft) | 0, l = l + Math.imul(se, _e) | 0, y = y + Math.imul(se, ft) | 0, k = k + Math.imul(P, Me) | 0, l = l + Math.imul(P, lt) | 0, l = l + Math.imul(J, Me) | 0, y = y + Math.imul(J, lt) | 0;
        var Ar = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Ar >>> 26) | 0, Ar &= 67108863, k = Math.imul(T, H), l = Math.imul(T, ae), l = l + Math.imul(L, H) | 0, y = Math.imul(L, ae), k = k + Math.imul(B, ie) | 0, l = l + Math.imul(B, ve) | 0, l = l + Math.imul(b, ie) | 0, y = y + Math.imul(b, ve) | 0, k = k + Math.imul(de, we) | 0, l = l + Math.imul(de, $e) | 0, l = l + Math.imul(Te, we) | 0, y = y + Math.imul(Te, $e) | 0, k = k + Math.imul(ce, xe) | 0, l = l + Math.imul(ce, tt) | 0, l = l + Math.imul(Pe, xe) | 0, y = y + Math.imul(Pe, tt) | 0, k = k + Math.imul(me, ke) | 0, l = l + Math.imul(me, it) | 0, l = l + Math.imul(He, ke) | 0, y = y + Math.imul(He, it) | 0, k = k + Math.imul(fe, Se) | 0, l = l + Math.imul(fe, nt) | 0, l = l + Math.imul(Re, Se) | 0, y = y + Math.imul(Re, nt) | 0, k = k + Math.imul(he, Ae) | 0, l = l + Math.imul(he, st) | 0, l = l + Math.imul(Ee, Ae) | 0, y = y + Math.imul(Ee, st) | 0, k = k + Math.imul(ne, _e) | 0, l = l + Math.imul(ne, ft) | 0, l = l + Math.imul(Ne, _e) | 0, y = y + Math.imul(Ne, ft) | 0, k = k + Math.imul(Q, Me) | 0, l = l + Math.imul(Q, lt) | 0, l = l + Math.imul(se, Me) | 0, y = y + Math.imul(se, lt) | 0, k = k + Math.imul(P, Be) | 0, l = l + Math.imul(P, dt) | 0, l = l + Math.imul(J, Be) | 0, y = y + Math.imul(J, dt) | 0;
        var _r = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (_r >>> 26) | 0, _r &= 67108863, k = Math.imul(T, ie), l = Math.imul(T, ve), l = l + Math.imul(L, ie) | 0, y = Math.imul(L, ve), k = k + Math.imul(B, we) | 0, l = l + Math.imul(B, $e) | 0, l = l + Math.imul(b, we) | 0, y = y + Math.imul(b, $e) | 0, k = k + Math.imul(de, xe) | 0, l = l + Math.imul(de, tt) | 0, l = l + Math.imul(Te, xe) | 0, y = y + Math.imul(Te, tt) | 0, k = k + Math.imul(ce, ke) | 0, l = l + Math.imul(ce, it) | 0, l = l + Math.imul(Pe, ke) | 0, y = y + Math.imul(Pe, it) | 0, k = k + Math.imul(me, Se) | 0, l = l + Math.imul(me, nt) | 0, l = l + Math.imul(He, Se) | 0, y = y + Math.imul(He, nt) | 0, k = k + Math.imul(fe, Ae) | 0, l = l + Math.imul(fe, st) | 0, l = l + Math.imul(Re, Ae) | 0, y = y + Math.imul(Re, st) | 0, k = k + Math.imul(he, _e) | 0, l = l + Math.imul(he, ft) | 0, l = l + Math.imul(Ee, _e) | 0, y = y + Math.imul(Ee, ft) | 0, k = k + Math.imul(ne, Me) | 0, l = l + Math.imul(ne, lt) | 0, l = l + Math.imul(Ne, Me) | 0, y = y + Math.imul(Ne, lt) | 0, k = k + Math.imul(Q, Be) | 0, l = l + Math.imul(Q, dt) | 0, l = l + Math.imul(se, Be) | 0, y = y + Math.imul(se, dt) | 0;
        var Mr = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Mr >>> 26) | 0, Mr &= 67108863, k = Math.imul(T, we), l = Math.imul(T, $e), l = l + Math.imul(L, we) | 0, y = Math.imul(L, $e), k = k + Math.imul(B, xe) | 0, l = l + Math.imul(B, tt) | 0, l = l + Math.imul(b, xe) | 0, y = y + Math.imul(b, tt) | 0, k = k + Math.imul(de, ke) | 0, l = l + Math.imul(de, it) | 0, l = l + Math.imul(Te, ke) | 0, y = y + Math.imul(Te, it) | 0, k = k + Math.imul(ce, Se) | 0, l = l + Math.imul(ce, nt) | 0, l = l + Math.imul(Pe, Se) | 0, y = y + Math.imul(Pe, nt) | 0, k = k + Math.imul(me, Ae) | 0, l = l + Math.imul(me, st) | 0, l = l + Math.imul(He, Ae) | 0, y = y + Math.imul(He, st) | 0, k = k + Math.imul(fe, _e) | 0, l = l + Math.imul(fe, ft) | 0, l = l + Math.imul(Re, _e) | 0, y = y + Math.imul(Re, ft) | 0, k = k + Math.imul(he, Me) | 0, l = l + Math.imul(he, lt) | 0, l = l + Math.imul(Ee, Me) | 0, y = y + Math.imul(Ee, lt) | 0, k = k + Math.imul(ne, Be) | 0, l = l + Math.imul(ne, dt) | 0, l = l + Math.imul(Ne, Be) | 0, y = y + Math.imul(Ne, dt) | 0;
        var Br = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Br >>> 26) | 0, Br &= 67108863, k = Math.imul(T, xe), l = Math.imul(T, tt), l = l + Math.imul(L, xe) | 0, y = Math.imul(L, tt), k = k + Math.imul(B, ke) | 0, l = l + Math.imul(B, it) | 0, l = l + Math.imul(b, ke) | 0, y = y + Math.imul(b, it) | 0, k = k + Math.imul(de, Se) | 0, l = l + Math.imul(de, nt) | 0, l = l + Math.imul(Te, Se) | 0, y = y + Math.imul(Te, nt) | 0, k = k + Math.imul(ce, Ae) | 0, l = l + Math.imul(ce, st) | 0, l = l + Math.imul(Pe, Ae) | 0, y = y + Math.imul(Pe, st) | 0, k = k + Math.imul(me, _e) | 0, l = l + Math.imul(me, ft) | 0, l = l + Math.imul(He, _e) | 0, y = y + Math.imul(He, ft) | 0, k = k + Math.imul(fe, Me) | 0, l = l + Math.imul(fe, lt) | 0, l = l + Math.imul(Re, Me) | 0, y = y + Math.imul(Re, lt) | 0, k = k + Math.imul(he, Be) | 0, l = l + Math.imul(he, dt) | 0, l = l + Math.imul(Ee, Be) | 0, y = y + Math.imul(Ee, dt) | 0;
        var Ir = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Ir >>> 26) | 0, Ir &= 67108863, k = Math.imul(T, ke), l = Math.imul(T, it), l = l + Math.imul(L, ke) | 0, y = Math.imul(L, it), k = k + Math.imul(B, Se) | 0, l = l + Math.imul(B, nt) | 0, l = l + Math.imul(b, Se) | 0, y = y + Math.imul(b, nt) | 0, k = k + Math.imul(de, Ae) | 0, l = l + Math.imul(de, st) | 0, l = l + Math.imul(Te, Ae) | 0, y = y + Math.imul(Te, st) | 0, k = k + Math.imul(ce, _e) | 0, l = l + Math.imul(ce, ft) | 0, l = l + Math.imul(Pe, _e) | 0, y = y + Math.imul(Pe, ft) | 0, k = k + Math.imul(me, Me) | 0, l = l + Math.imul(me, lt) | 0, l = l + Math.imul(He, Me) | 0, y = y + Math.imul(He, lt) | 0, k = k + Math.imul(fe, Be) | 0, l = l + Math.imul(fe, dt) | 0, l = l + Math.imul(Re, Be) | 0, y = y + Math.imul(Re, dt) | 0;
        var Er = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Er >>> 26) | 0, Er &= 67108863, k = Math.imul(T, Se), l = Math.imul(T, nt), l = l + Math.imul(L, Se) | 0, y = Math.imul(L, nt), k = k + Math.imul(B, Ae) | 0, l = l + Math.imul(B, st) | 0, l = l + Math.imul(b, Ae) | 0, y = y + Math.imul(b, st) | 0, k = k + Math.imul(de, _e) | 0, l = l + Math.imul(de, ft) | 0, l = l + Math.imul(Te, _e) | 0, y = y + Math.imul(Te, ft) | 0, k = k + Math.imul(ce, Me) | 0, l = l + Math.imul(ce, lt) | 0, l = l + Math.imul(Pe, Me) | 0, y = y + Math.imul(Pe, lt) | 0, k = k + Math.imul(me, Be) | 0, l = l + Math.imul(me, dt) | 0, l = l + Math.imul(He, Be) | 0, y = y + Math.imul(He, dt) | 0;
        var Pr = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Pr >>> 26) | 0, Pr &= 67108863, k = Math.imul(T, Ae), l = Math.imul(T, st), l = l + Math.imul(L, Ae) | 0, y = Math.imul(L, st), k = k + Math.imul(B, _e) | 0, l = l + Math.imul(B, ft) | 0, l = l + Math.imul(b, _e) | 0, y = y + Math.imul(b, ft) | 0, k = k + Math.imul(de, Me) | 0, l = l + Math.imul(de, lt) | 0, l = l + Math.imul(Te, Me) | 0, y = y + Math.imul(Te, lt) | 0, k = k + Math.imul(ce, Be) | 0, l = l + Math.imul(ce, dt) | 0, l = l + Math.imul(Pe, Be) | 0, y = y + Math.imul(Pe, dt) | 0;
        var Tr = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Tr >>> 26) | 0, Tr &= 67108863, k = Math.imul(T, _e), l = Math.imul(T, ft), l = l + Math.imul(L, _e) | 0, y = Math.imul(L, ft), k = k + Math.imul(B, Me) | 0, l = l + Math.imul(B, lt) | 0, l = l + Math.imul(b, Me) | 0, y = y + Math.imul(b, lt) | 0, k = k + Math.imul(de, Be) | 0, l = l + Math.imul(de, dt) | 0, l = l + Math.imul(Te, Be) | 0, y = y + Math.imul(Te, dt) | 0;
        var zr = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (zr >>> 26) | 0, zr &= 67108863, k = Math.imul(T, Me), l = Math.imul(T, lt), l = l + Math.imul(L, Me) | 0, y = Math.imul(L, lt), k = k + Math.imul(B, Be) | 0, l = l + Math.imul(B, dt) | 0, l = l + Math.imul(b, Be) | 0, y = y + Math.imul(b, dt) | 0;
        var Or = (A + k | 0) + ((l & 8191) << 13) | 0;
        A = (y + (l >>> 13) | 0) + (Or >>> 26) | 0, Or &= 67108863, k = Math.imul(T, Be), l = Math.imul(T, dt), l = l + Math.imul(L, Be) | 0, y = Math.imul(L, dt);
        var Nr = (A + k | 0) + ((l & 8191) << 13) | 0;
        return A = (y + (l >>> 13) | 0) + (Nr >>> 26) | 0, Nr &= 67108863, w[0] = Ze, w[1] = Qe, w[2] = gr, w[3] = yr, w[4] = wr, w[5] = xr, w[6] = kr, w[7] = Sr, w[8] = Ar, w[9] = _r, w[10] = Mr, w[11] = Br, w[12] = Ir, w[13] = Er, w[14] = Pr, w[15] = Tr, w[16] = zr, w[17] = Or, w[18] = Nr, A !== 0 && (w[19] = A, n.length++), n;
      };
      Math.imul || (E = _);
      function O(z, f, u) {
        u.negative = f.negative ^ z.negative, u.length = z.length + f.length;
        for (var n = 0, s = 0, d = 0; d < u.length - 1; d++) {
          var w = s;
          s = 0;
          for (var A = n & 67108863, k = Math.min(d, f.length - 1), l = Math.max(0, d - z.length + 1); l <= k; l++) {
            var y = d - l, v = z.words[y] | 0, P = f.words[l] | 0, J = v * P, Y = J & 67108863;
            w = w + (J / 67108864 | 0) | 0, Y = Y + A | 0, A = Y & 67108863, w = w + (Y >>> 26) | 0, s += w >>> 26, w &= 67108863;
          }
          u.words[d] = A, n = w, w = s;
        }
        return n !== 0 ? u.words[d] = n : u.length--, u.strip();
      }
      function N(z, f, u) {
        var n = new U();
        return n.mulp(z, f, u);
      }
      a.prototype.mulTo = function(f, u) {
        var n, s = this.length + f.length;
        return this.length === 10 && f.length === 10 ? n = E(this, f, u) : s < 63 ? n = _(this, f, u) : s < 1024 ? n = O(this, f, u) : n = N(this, f, u), n;
      };
      function U(z, f) {
        this.x = z, this.y = f;
      }
      U.prototype.makeRBT = function(f) {
        for (var u = new Array(f), n = a.prototype._countBits(f) - 1, s = 0; s < f; s++)
          u[s] = this.revBin(s, n, f);
        return u;
      }, U.prototype.revBin = function(f, u, n) {
        if (f === 0 || f === n - 1) return f;
        for (var s = 0, d = 0; d < u; d++)
          s |= (f & 1) << u - d - 1, f >>= 1;
        return s;
      }, U.prototype.permute = function(f, u, n, s, d, w) {
        for (var A = 0; A < w; A++)
          s[A] = u[f[A]], d[A] = n[f[A]];
      }, U.prototype.transform = function(f, u, n, s, d, w) {
        this.permute(w, f, u, n, s, d);
        for (var A = 1; A < d; A <<= 1)
          for (var k = A << 1, l = Math.cos(2 * Math.PI / k), y = Math.sin(2 * Math.PI / k), v = 0; v < d; v += k)
            for (var P = l, J = y, Y = 0; Y < A; Y++) {
              var Q = n[v + Y], se = s[v + Y], pe = n[v + Y + A], ne = s[v + Y + A], Ne = P * pe - J * ne;
              ne = P * ne + J * pe, pe = Ne, n[v + Y] = Q + pe, s[v + Y] = se + ne, n[v + Y + A] = Q - pe, s[v + Y + A] = se - ne, Y !== k && (Ne = l * P - y * J, J = l * J + y * P, P = Ne);
            }
      }, U.prototype.guessLen13b = function(f, u) {
        var n = Math.max(u, f) | 1, s = n & 1, d = 0;
        for (n = n / 2 | 0; n; n = n >>> 1)
          d++;
        return 1 << d + 1 + s;
      }, U.prototype.conjugate = function(f, u, n) {
        if (!(n <= 1))
          for (var s = 0; s < n / 2; s++) {
            var d = f[s];
            f[s] = f[n - s - 1], f[n - s - 1] = d, d = u[s], u[s] = -u[n - s - 1], u[n - s - 1] = -d;
          }
      }, U.prototype.normalize13b = function(f, u) {
        for (var n = 0, s = 0; s < u / 2; s++) {
          var d = Math.round(f[2 * s + 1] / u) * 8192 + Math.round(f[2 * s] / u) + n;
          f[s] = d & 67108863, d < 67108864 ? n = 0 : n = d / 67108864 | 0;
        }
        return f;
      }, U.prototype.convert13b = function(f, u, n, s) {
        for (var d = 0, w = 0; w < u; w++)
          d = d + (f[w] | 0), n[2 * w] = d & 8191, d = d >>> 13, n[2 * w + 1] = d & 8191, d = d >>> 13;
        for (w = 2 * u; w < s; ++w)
          n[w] = 0;
        i(d === 0), i((d & -8192) === 0);
      }, U.prototype.stub = function(f) {
        for (var u = new Array(f), n = 0; n < f; n++)
          u[n] = 0;
        return u;
      }, U.prototype.mulp = function(f, u, n) {
        var s = 2 * this.guessLen13b(f.length, u.length), d = this.makeRBT(s), w = this.stub(s), A = new Array(s), k = new Array(s), l = new Array(s), y = new Array(s), v = new Array(s), P = new Array(s), J = n.words;
        J.length = s, this.convert13b(f.words, f.length, A, s), this.convert13b(u.words, u.length, y, s), this.transform(A, w, k, l, s, d), this.transform(y, w, v, P, s, d);
        for (var Y = 0; Y < s; Y++) {
          var Q = k[Y] * v[Y] - l[Y] * P[Y];
          l[Y] = k[Y] * P[Y] + l[Y] * v[Y], k[Y] = Q;
        }
        return this.conjugate(k, l, s), this.transform(k, l, J, w, s, d), this.conjugate(J, w, s), this.normalize13b(J, s), n.negative = f.negative ^ u.negative, n.length = f.length + u.length, n.strip();
      }, a.prototype.mul = function(f) {
        var u = new a(null);
        return u.words = new Array(this.length + f.length), this.mulTo(f, u);
      }, a.prototype.mulf = function(f) {
        var u = new a(null);
        return u.words = new Array(this.length + f.length), N(this, f, u);
      }, a.prototype.imul = function(f) {
        return this.clone().mulTo(f, this);
      }, a.prototype.imuln = function(f) {
        i(typeof f == "number"), i(f < 67108864);
        for (var u = 0, n = 0; n < this.length; n++) {
          var s = (this.words[n] | 0) * f, d = (s & 67108863) + (u & 67108863);
          u >>= 26, u += s / 67108864 | 0, u += d >>> 26, this.words[n] = d & 67108863;
        }
        return u !== 0 && (this.words[n] = u, this.length++), this.length = f === 0 ? 1 : this.length, this;
      }, a.prototype.muln = function(f) {
        return this.clone().imuln(f);
      }, a.prototype.sqr = function() {
        return this.mul(this);
      }, a.prototype.isqr = function() {
        return this.imul(this.clone());
      }, a.prototype.pow = function(f) {
        var u = I(f);
        if (u.length === 0) return new a(1);
        for (var n = this, s = 0; s < u.length && u[s] === 0; s++, n = n.sqr())
          ;
        if (++s < u.length)
          for (var d = n.sqr(); s < u.length; s++, d = d.sqr())
            u[s] !== 0 && (n = n.mul(d));
        return n;
      }, a.prototype.iushln = function(f) {
        i(typeof f == "number" && f >= 0);
        var u = f % 26, n = (f - u) / 26, s = 67108863 >>> 26 - u << 26 - u, d;
        if (u !== 0) {
          var w = 0;
          for (d = 0; d < this.length; d++) {
            var A = this.words[d] & s, k = (this.words[d] | 0) - A << u;
            this.words[d] = k | w, w = A >>> 26 - u;
          }
          w && (this.words[d] = w, this.length++);
        }
        if (n !== 0) {
          for (d = this.length - 1; d >= 0; d--)
            this.words[d + n] = this.words[d];
          for (d = 0; d < n; d++)
            this.words[d] = 0;
          this.length += n;
        }
        return this.strip();
      }, a.prototype.ishln = function(f) {
        return i(this.negative === 0), this.iushln(f);
      }, a.prototype.iushrn = function(f, u, n) {
        i(typeof f == "number" && f >= 0);
        var s;
        u ? s = (u - u % 26) / 26 : s = 0;
        var d = f % 26, w = Math.min((f - d) / 26, this.length), A = 67108863 ^ 67108863 >>> d << d, k = n;
        if (s -= w, s = Math.max(0, s), k) {
          for (var l = 0; l < w; l++)
            k.words[l] = this.words[l];
          k.length = w;
        }
        if (w !== 0) if (this.length > w)
          for (this.length -= w, l = 0; l < this.length; l++)
            this.words[l] = this.words[l + w];
        else
          this.words[0] = 0, this.length = 1;
        var y = 0;
        for (l = this.length - 1; l >= 0 && (y !== 0 || l >= s); l--) {
          var v = this.words[l] | 0;
          this.words[l] = y << 26 - d | v >>> d, y = v & A;
        }
        return k && y !== 0 && (k.words[k.length++] = y), this.length === 0 && (this.words[0] = 0, this.length = 1), this.strip();
      }, a.prototype.ishrn = function(f, u, n) {
        return i(this.negative === 0), this.iushrn(f, u, n);
      }, a.prototype.shln = function(f) {
        return this.clone().ishln(f);
      }, a.prototype.ushln = function(f) {
        return this.clone().iushln(f);
      }, a.prototype.shrn = function(f) {
        return this.clone().ishrn(f);
      }, a.prototype.ushrn = function(f) {
        return this.clone().iushrn(f);
      }, a.prototype.testn = function(f) {
        i(typeof f == "number" && f >= 0);
        var u = f % 26, n = (f - u) / 26, s = 1 << u;
        if (this.length <= n) return !1;
        var d = this.words[n];
        return !!(d & s);
      }, a.prototype.imaskn = function(f) {
        i(typeof f == "number" && f >= 0);
        var u = f % 26, n = (f - u) / 26;
        if (i(this.negative === 0, "imaskn works only with positive numbers"), this.length <= n)
          return this;
        if (u !== 0 && n++, this.length = Math.min(n, this.length), u !== 0) {
          var s = 67108863 ^ 67108863 >>> u << u;
          this.words[this.length - 1] &= s;
        }
        return this.strip();
      }, a.prototype.maskn = function(f) {
        return this.clone().imaskn(f);
      }, a.prototype.iaddn = function(f) {
        return i(typeof f == "number"), i(f < 67108864), f < 0 ? this.isubn(-f) : this.negative !== 0 ? this.length === 1 && (this.words[0] | 0) < f ? (this.words[0] = f - (this.words[0] | 0), this.negative = 0, this) : (this.negative = 0, this.isubn(f), this.negative = 1, this) : this._iaddn(f);
      }, a.prototype._iaddn = function(f) {
        this.words[0] += f;
        for (var u = 0; u < this.length && this.words[u] >= 67108864; u++)
          this.words[u] -= 67108864, u === this.length - 1 ? this.words[u + 1] = 1 : this.words[u + 1]++;
        return this.length = Math.max(this.length, u + 1), this;
      }, a.prototype.isubn = function(f) {
        if (i(typeof f == "number"), i(f < 67108864), f < 0) return this.iaddn(-f);
        if (this.negative !== 0)
          return this.negative = 0, this.iaddn(f), this.negative = 1, this;
        if (this.words[0] -= f, this.length === 1 && this.words[0] < 0)
          this.words[0] = -this.words[0], this.negative = 1;
        else
          for (var u = 0; u < this.length && this.words[u] < 0; u++)
            this.words[u] += 67108864, this.words[u + 1] -= 1;
        return this.strip();
      }, a.prototype.addn = function(f) {
        return this.clone().iaddn(f);
      }, a.prototype.subn = function(f) {
        return this.clone().isubn(f);
      }, a.prototype.iabs = function() {
        return this.negative = 0, this;
      }, a.prototype.abs = function() {
        return this.clone().iabs();
      }, a.prototype._ishlnsubmul = function(f, u, n) {
        var s = f.length + n, d;
        this._expand(s);
        var w, A = 0;
        for (d = 0; d < f.length; d++) {
          w = (this.words[d + n] | 0) + A;
          var k = (f.words[d] | 0) * u;
          w -= k & 67108863, A = (w >> 26) - (k / 67108864 | 0), this.words[d + n] = w & 67108863;
        }
        for (; d < this.length - n; d++)
          w = (this.words[d + n] | 0) + A, A = w >> 26, this.words[d + n] = w & 67108863;
        if (A === 0) return this.strip();
        for (i(A === -1), A = 0, d = 0; d < this.length; d++)
          w = -(this.words[d] | 0) + A, A = w >> 26, this.words[d] = w & 67108863;
        return this.negative = 1, this.strip();
      }, a.prototype._wordDiv = function(f, u) {
        var n = this.length - f.length, s = this.clone(), d = f, w = d.words[d.length - 1] | 0, A = this._countBits(w);
        n = 26 - A, n !== 0 && (d = d.ushln(n), s.iushln(n), w = d.words[d.length - 1] | 0);
        var k = s.length - d.length, l;
        if (u !== "mod") {
          l = new a(null), l.length = k + 1, l.words = new Array(l.length);
          for (var y = 0; y < l.length; y++)
            l.words[y] = 0;
        }
        var v = s.clone()._ishlnsubmul(d, 1, k);
        v.negative === 0 && (s = v, l && (l.words[k] = 1));
        for (var P = k - 1; P >= 0; P--) {
          var J = (s.words[d.length + P] | 0) * 67108864 + (s.words[d.length + P - 1] | 0);
          for (J = Math.min(J / w | 0, 67108863), s._ishlnsubmul(d, J, P); s.negative !== 0; )
            J--, s.negative = 0, s._ishlnsubmul(d, 1, P), s.isZero() || (s.negative ^= 1);
          l && (l.words[P] = J);
        }
        return l && l.strip(), s.strip(), u !== "div" && n !== 0 && s.iushrn(n), {
          div: l || null,
          mod: s
        };
      }, a.prototype.divmod = function(f, u, n) {
        if (i(!f.isZero()), this.isZero())
          return {
            div: new a(0),
            mod: new a(0)
          };
        var s, d, w;
        return this.negative !== 0 && f.negative === 0 ? (w = this.neg().divmod(f, u), u !== "mod" && (s = w.div.neg()), u !== "div" && (d = w.mod.neg(), n && d.negative !== 0 && d.iadd(f)), {
          div: s,
          mod: d
        }) : this.negative === 0 && f.negative !== 0 ? (w = this.divmod(f.neg(), u), u !== "mod" && (s = w.div.neg()), {
          div: s,
          mod: w.mod
        }) : (this.negative & f.negative) !== 0 ? (w = this.neg().divmod(f.neg(), u), u !== "div" && (d = w.mod.neg(), n && d.negative !== 0 && d.isub(f)), {
          div: w.div,
          mod: d
        }) : f.length > this.length || this.cmp(f) < 0 ? {
          div: new a(0),
          mod: this
        } : f.length === 1 ? u === "div" ? {
          div: this.divn(f.words[0]),
          mod: null
        } : u === "mod" ? {
          div: null,
          mod: new a(this.modn(f.words[0]))
        } : {
          div: this.divn(f.words[0]),
          mod: new a(this.modn(f.words[0]))
        } : this._wordDiv(f, u);
      }, a.prototype.div = function(f) {
        return this.divmod(f, "div", !1).div;
      }, a.prototype.mod = function(f) {
        return this.divmod(f, "mod", !1).mod;
      }, a.prototype.umod = function(f) {
        return this.divmod(f, "mod", !0).mod;
      }, a.prototype.divRound = function(f) {
        var u = this.divmod(f);
        if (u.mod.isZero()) return u.div;
        var n = u.div.negative !== 0 ? u.mod.isub(f) : u.mod, s = f.ushrn(1), d = f.andln(1), w = n.cmp(s);
        return w < 0 || d === 1 && w === 0 ? u.div : u.div.negative !== 0 ? u.div.isubn(1) : u.div.iaddn(1);
      }, a.prototype.modn = function(f) {
        i(f <= 67108863);
        for (var u = (1 << 26) % f, n = 0, s = this.length - 1; s >= 0; s--)
          n = (u * n + (this.words[s] | 0)) % f;
        return n;
      }, a.prototype.idivn = function(f) {
        i(f <= 67108863);
        for (var u = 0, n = this.length - 1; n >= 0; n--) {
          var s = (this.words[n] | 0) + u * 67108864;
          this.words[n] = s / f | 0, u = s % f;
        }
        return this.strip();
      }, a.prototype.divn = function(f) {
        return this.clone().idivn(f);
      }, a.prototype.egcd = function(f) {
        i(f.negative === 0), i(!f.isZero());
        var u = this, n = f.clone();
        u.negative !== 0 ? u = u.umod(f) : u = u.clone();
        for (var s = new a(1), d = new a(0), w = new a(0), A = new a(1), k = 0; u.isEven() && n.isEven(); )
          u.iushrn(1), n.iushrn(1), ++k;
        for (var l = n.clone(), y = u.clone(); !u.isZero(); ) {
          for (var v = 0, P = 1; (u.words[0] & P) === 0 && v < 26; ++v, P <<= 1) ;
          if (v > 0)
            for (u.iushrn(v); v-- > 0; )
              (s.isOdd() || d.isOdd()) && (s.iadd(l), d.isub(y)), s.iushrn(1), d.iushrn(1);
          for (var J = 0, Y = 1; (n.words[0] & Y) === 0 && J < 26; ++J, Y <<= 1) ;
          if (J > 0)
            for (n.iushrn(J); J-- > 0; )
              (w.isOdd() || A.isOdd()) && (w.iadd(l), A.isub(y)), w.iushrn(1), A.iushrn(1);
          u.cmp(n) >= 0 ? (u.isub(n), s.isub(w), d.isub(A)) : (n.isub(u), w.isub(s), A.isub(d));
        }
        return {
          a: w,
          b: A,
          gcd: n.iushln(k)
        };
      }, a.prototype._invmp = function(f) {
        i(f.negative === 0), i(!f.isZero());
        var u = this, n = f.clone();
        u.negative !== 0 ? u = u.umod(f) : u = u.clone();
        for (var s = new a(1), d = new a(0), w = n.clone(); u.cmpn(1) > 0 && n.cmpn(1) > 0; ) {
          for (var A = 0, k = 1; (u.words[0] & k) === 0 && A < 26; ++A, k <<= 1) ;
          if (A > 0)
            for (u.iushrn(A); A-- > 0; )
              s.isOdd() && s.iadd(w), s.iushrn(1);
          for (var l = 0, y = 1; (n.words[0] & y) === 0 && l < 26; ++l, y <<= 1) ;
          if (l > 0)
            for (n.iushrn(l); l-- > 0; )
              d.isOdd() && d.iadd(w), d.iushrn(1);
          u.cmp(n) >= 0 ? (u.isub(n), s.isub(d)) : (n.isub(u), d.isub(s));
        }
        var v;
        return u.cmpn(1) === 0 ? v = s : v = d, v.cmpn(0) < 0 && v.iadd(f), v;
      }, a.prototype.gcd = function(f) {
        if (this.isZero()) return f.abs();
        if (f.isZero()) return this.abs();
        var u = this.clone(), n = f.clone();
        u.negative = 0, n.negative = 0;
        for (var s = 0; u.isEven() && n.isEven(); s++)
          u.iushrn(1), n.iushrn(1);
        do {
          for (; u.isEven(); )
            u.iushrn(1);
          for (; n.isEven(); )
            n.iushrn(1);
          var d = u.cmp(n);
          if (d < 0) {
            var w = u;
            u = n, n = w;
          } else if (d === 0 || n.cmpn(1) === 0)
            break;
          u.isub(n);
        } while (!0);
        return n.iushln(s);
      }, a.prototype.invm = function(f) {
        return this.egcd(f).a.umod(f);
      }, a.prototype.isEven = function() {
        return (this.words[0] & 1) === 0;
      }, a.prototype.isOdd = function() {
        return (this.words[0] & 1) === 1;
      }, a.prototype.andln = function(f) {
        return this.words[0] & f;
      }, a.prototype.bincn = function(f) {
        i(typeof f == "number");
        var u = f % 26, n = (f - u) / 26, s = 1 << u;
        if (this.length <= n)
          return this._expand(n + 1), this.words[n] |= s, this;
        for (var d = s, w = n; d !== 0 && w < this.length; w++) {
          var A = this.words[w] | 0;
          A += d, d = A >>> 26, A &= 67108863, this.words[w] = A;
        }
        return d !== 0 && (this.words[w] = d, this.length++), this;
      }, a.prototype.isZero = function() {
        return this.length === 1 && this.words[0] === 0;
      }, a.prototype.cmpn = function(f) {
        var u = f < 0;
        if (this.negative !== 0 && !u) return -1;
        if (this.negative === 0 && u) return 1;
        this.strip();
        var n;
        if (this.length > 1)
          n = 1;
        else {
          u && (f = -f), i(f <= 67108863, "Number is too big");
          var s = this.words[0] | 0;
          n = s === f ? 0 : s < f ? -1 : 1;
        }
        return this.negative !== 0 ? -n | 0 : n;
      }, a.prototype.cmp = function(f) {
        if (this.negative !== 0 && f.negative === 0) return -1;
        if (this.negative === 0 && f.negative !== 0) return 1;
        var u = this.ucmp(f);
        return this.negative !== 0 ? -u | 0 : u;
      }, a.prototype.ucmp = function(f) {
        if (this.length > f.length) return 1;
        if (this.length < f.length) return -1;
        for (var u = 0, n = this.length - 1; n >= 0; n--) {
          var s = this.words[n] | 0, d = f.words[n] | 0;
          if (s !== d) {
            s < d ? u = -1 : s > d && (u = 1);
            break;
          }
        }
        return u;
      }, a.prototype.gtn = function(f) {
        return this.cmpn(f) === 1;
      }, a.prototype.gt = function(f) {
        return this.cmp(f) === 1;
      }, a.prototype.gten = function(f) {
        return this.cmpn(f) >= 0;
      }, a.prototype.gte = function(f) {
        return this.cmp(f) >= 0;
      }, a.prototype.ltn = function(f) {
        return this.cmpn(f) === -1;
      }, a.prototype.lt = function(f) {
        return this.cmp(f) === -1;
      }, a.prototype.lten = function(f) {
        return this.cmpn(f) <= 0;
      }, a.prototype.lte = function(f) {
        return this.cmp(f) <= 0;
      }, a.prototype.eqn = function(f) {
        return this.cmpn(f) === 0;
      }, a.prototype.eq = function(f) {
        return this.cmp(f) === 0;
      }, a.red = function(f) {
        return new K(f);
      }, a.prototype.toRed = function(f) {
        return i(!this.red, "Already a number in reduction context"), i(this.negative === 0, "red works only with positives"), f.convertTo(this)._forceRed(f);
      }, a.prototype.fromRed = function() {
        return i(this.red, "fromRed works only with numbers in reduction context"), this.red.convertFrom(this);
      }, a.prototype._forceRed = function(f) {
        return this.red = f, this;
      }, a.prototype.forceRed = function(f) {
        return i(!this.red, "Already a number in reduction context"), this._forceRed(f);
      }, a.prototype.redAdd = function(f) {
        return i(this.red, "redAdd works only with red numbers"), this.red.add(this, f);
      }, a.prototype.redIAdd = function(f) {
        return i(this.red, "redIAdd works only with red numbers"), this.red.iadd(this, f);
      }, a.prototype.redSub = function(f) {
        return i(this.red, "redSub works only with red numbers"), this.red.sub(this, f);
      }, a.prototype.redISub = function(f) {
        return i(this.red, "redISub works only with red numbers"), this.red.isub(this, f);
      }, a.prototype.redShl = function(f) {
        return i(this.red, "redShl works only with red numbers"), this.red.shl(this, f);
      }, a.prototype.redMul = function(f) {
        return i(this.red, "redMul works only with red numbers"), this.red._verify2(this, f), this.red.mul(this, f);
      }, a.prototype.redIMul = function(f) {
        return i(this.red, "redMul works only with red numbers"), this.red._verify2(this, f), this.red.imul(this, f);
      }, a.prototype.redSqr = function() {
        return i(this.red, "redSqr works only with red numbers"), this.red._verify1(this), this.red.sqr(this);
      }, a.prototype.redISqr = function() {
        return i(this.red, "redISqr works only with red numbers"), this.red._verify1(this), this.red.isqr(this);
      }, a.prototype.redSqrt = function() {
        return i(this.red, "redSqrt works only with red numbers"), this.red._verify1(this), this.red.sqrt(this);
      }, a.prototype.redInvm = function() {
        return i(this.red, "redInvm works only with red numbers"), this.red._verify1(this), this.red.invm(this);
      }, a.prototype.redNeg = function() {
        return i(this.red, "redNeg works only with red numbers"), this.red._verify1(this), this.red.neg(this);
      }, a.prototype.redPow = function(f) {
        return i(this.red && !f.red, "redPow(normalNum)"), this.red._verify1(this), this.red.pow(this, f);
      };
      var j = {
        k256: null,
        p224: null,
        p192: null,
        p25519: null
      };
      function F(z, f) {
        this.name = z, this.p = new a(f, 16), this.n = this.p.bitLength(), this.k = new a(1).iushln(this.n).isub(this.p), this.tmp = this._tmp();
      }
      F.prototype._tmp = function() {
        var f = new a(null);
        return f.words = new Array(Math.ceil(this.n / 13)), f;
      }, F.prototype.ireduce = function(f) {
        var u = f, n;
        do
          this.split(u, this.tmp), u = this.imulK(u), u = u.iadd(this.tmp), n = u.bitLength();
        while (n > this.n);
        var s = n < this.n ? -1 : u.ucmp(this.p);
        return s === 0 ? (u.words[0] = 0, u.length = 1) : s > 0 ? u.isub(this.p) : u.strip !== void 0 ? u.strip() : u._strip(), u;
      }, F.prototype.split = function(f, u) {
        f.iushrn(this.n, 0, u);
      }, F.prototype.imulK = function(f) {
        return f.imul(this.k);
      };
      function C() {
        F.call(
          this,
          "k256",
          "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f"
        );
      }
      o(C, F), C.prototype.split = function(f, u) {
        for (var n = 4194303, s = Math.min(f.length, 9), d = 0; d < s; d++)
          u.words[d] = f.words[d];
        if (u.length = s, f.length <= 9) {
          f.words[0] = 0, f.length = 1;
          return;
        }
        var w = f.words[9];
        for (u.words[u.length++] = w & n, d = 10; d < f.length; d++) {
          var A = f.words[d] | 0;
          f.words[d - 10] = (A & n) << 4 | w >>> 22, w = A;
        }
        w >>>= 22, f.words[d - 10] = w, w === 0 && f.length > 10 ? f.length -= 10 : f.length -= 9;
      }, C.prototype.imulK = function(f) {
        f.words[f.length] = 0, f.words[f.length + 1] = 0, f.length += 2;
        for (var u = 0, n = 0; n < f.length; n++) {
          var s = f.words[n] | 0;
          u += s * 977, f.words[n] = u & 67108863, u = s * 64 + (u / 67108864 | 0);
        }
        return f.words[f.length - 1] === 0 && (f.length--, f.words[f.length - 1] === 0 && f.length--), f;
      };
      function q() {
        F.call(
          this,
          "p224",
          "ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001"
        );
      }
      o(q, F);
      function V() {
        F.call(
          this,
          "p192",
          "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff"
        );
      }
      o(V, F);
      function Z() {
        F.call(
          this,
          "25519",
          "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed"
        );
      }
      o(Z, F), Z.prototype.imulK = function(f) {
        for (var u = 0, n = 0; n < f.length; n++) {
          var s = (f.words[n] | 0) * 19 + u, d = s & 67108863;
          s >>>= 26, f.words[n] = d, u = s;
        }
        return u !== 0 && (f.words[f.length++] = u), f;
      }, a._prime = function(f) {
        if (j[f]) return j[f];
        var u;
        if (f === "k256")
          u = new C();
        else if (f === "p224")
          u = new q();
        else if (f === "p192")
          u = new V();
        else if (f === "p25519")
          u = new Z();
        else
          throw new Error("Unknown prime " + f);
        return j[f] = u, u;
      };
      function K(z) {
        if (typeof z == "string") {
          var f = a._prime(z);
          this.m = f.p, this.prime = f;
        } else
          i(z.gtn(1), "modulus must be greater than 1"), this.m = z, this.prime = null;
      }
      K.prototype._verify1 = function(f) {
        i(f.negative === 0, "red works only with positives"), i(f.red, "red works only with red numbers");
      }, K.prototype._verify2 = function(f, u) {
        i((f.negative | u.negative) === 0, "red works only with positives"), i(
          f.red && f.red === u.red,
          "red works only with red numbers"
        );
      }, K.prototype.imod = function(f) {
        return this.prime ? this.prime.ireduce(f)._forceRed(this) : f.umod(this.m)._forceRed(this);
      }, K.prototype.neg = function(f) {
        return f.isZero() ? f.clone() : this.m.sub(f)._forceRed(this);
      }, K.prototype.add = function(f, u) {
        this._verify2(f, u);
        var n = f.add(u);
        return n.cmp(this.m) >= 0 && n.isub(this.m), n._forceRed(this);
      }, K.prototype.iadd = function(f, u) {
        this._verify2(f, u);
        var n = f.iadd(u);
        return n.cmp(this.m) >= 0 && n.isub(this.m), n;
      }, K.prototype.sub = function(f, u) {
        this._verify2(f, u);
        var n = f.sub(u);
        return n.cmpn(0) < 0 && n.iadd(this.m), n._forceRed(this);
      }, K.prototype.isub = function(f, u) {
        this._verify2(f, u);
        var n = f.isub(u);
        return n.cmpn(0) < 0 && n.iadd(this.m), n;
      }, K.prototype.shl = function(f, u) {
        return this._verify1(f), this.imod(f.ushln(u));
      }, K.prototype.imul = function(f, u) {
        return this._verify2(f, u), this.imod(f.imul(u));
      }, K.prototype.mul = function(f, u) {
        return this._verify2(f, u), this.imod(f.mul(u));
      }, K.prototype.isqr = function(f) {
        return this.imul(f, f.clone());
      }, K.prototype.sqr = function(f) {
        return this.mul(f, f);
      }, K.prototype.sqrt = function(f) {
        if (f.isZero()) return f.clone();
        var u = this.m.andln(3);
        if (i(u % 2 === 1), u === 3) {
          var n = this.m.add(new a(1)).iushrn(2);
          return this.pow(f, n);
        }
        for (var s = this.m.subn(1), d = 0; !s.isZero() && s.andln(1) === 0; )
          d++, s.iushrn(1);
        i(!s.isZero());
        var w = new a(1).toRed(this), A = w.redNeg(), k = this.m.subn(1).iushrn(1), l = this.m.bitLength();
        for (l = new a(2 * l * l).toRed(this); this.pow(l, k).cmp(A) !== 0; )
          l.redIAdd(A);
        for (var y = this.pow(l, s), v = this.pow(f, s.addn(1).iushrn(1)), P = this.pow(f, s), J = d; P.cmp(w) !== 0; ) {
          for (var Y = P, Q = 0; Y.cmp(w) !== 0; Q++)
            Y = Y.redSqr();
          i(Q < J);
          var se = this.pow(y, new a(1).iushln(J - Q - 1));
          v = v.redMul(se), y = se.redSqr(), P = P.redMul(y), J = Q;
        }
        return v;
      }, K.prototype.invm = function(f) {
        var u = f._invmp(this.m);
        return u.negative !== 0 ? (u.negative = 0, this.imod(u).redNeg()) : this.imod(u);
      }, K.prototype.pow = function(f, u) {
        if (u.isZero()) return new a(1).toRed(this);
        if (u.cmpn(1) === 0) return f.clone();
        var n = 4, s = new Array(1 << n);
        s[0] = new a(1).toRed(this), s[1] = f;
        for (var d = 2; d < s.length; d++)
          s[d] = this.mul(s[d - 1], f);
        var w = s[0], A = 0, k = 0, l = u.bitLength() % 26;
        for (l === 0 && (l = 26), d = u.length - 1; d >= 0; d--) {
          for (var y = u.words[d], v = l - 1; v >= 0; v--) {
            var P = y >> v & 1;
            if (w !== s[0] && (w = this.sqr(w)), P === 0 && A === 0) {
              k = 0;
              continue;
            }
            A <<= 1, A |= P, k++, !(k !== n && (d !== 0 || v !== 0)) && (w = this.mul(w, s[A]), k = 0, A = 0);
          }
          l = 26;
        }
        return w;
      }, K.prototype.convertTo = function(f) {
        var u = f.umod(this.m);
        return u === f ? u.clone() : u;
      }, K.prototype.convertFrom = function(f) {
        var u = f.clone();
        return u.red = null, u;
      }, a.mont = function(f) {
        return new G(f);
      };
      function G(z) {
        K.call(this, z), this.shift = this.m.bitLength(), this.shift % 26 !== 0 && (this.shift += 26 - this.shift % 26), this.r = new a(1).iushln(this.shift), this.r2 = this.imod(this.r.sqr()), this.rinv = this.r._invmp(this.m), this.minv = this.rinv.mul(this.r).isubn(1).div(this.m), this.minv = this.minv.umod(this.r), this.minv = this.r.sub(this.minv);
      }
      o(G, K), G.prototype.convertTo = function(f) {
        return this.imod(f.ushln(this.shift));
      }, G.prototype.convertFrom = function(f) {
        var u = this.imod(f.mul(this.rinv));
        return u.red = null, u;
      }, G.prototype.imul = function(f, u) {
        if (f.isZero() || u.isZero())
          return f.words[0] = 0, f.length = 1, f;
        var n = f.imul(u), s = n.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m), d = n.isub(s).iushrn(this.shift), w = d;
        return d.cmp(this.m) >= 0 ? w = d.isub(this.m) : d.cmpn(0) < 0 && (w = d.iadd(this.m)), w._forceRed(this);
      }, G.prototype.mul = function(f, u) {
        if (f.isZero() || u.isZero()) return new a(0)._forceRed(this);
        var n = f.mul(u), s = n.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m), d = n.isub(s).iushrn(this.shift), w = d;
        return d.cmp(this.m) >= 0 ? w = d.isub(this.m) : d.cmpn(0) < 0 && (w = d.iadd(this.m)), w._forceRed(this);
      }, G.prototype.invm = function(f) {
        var u = this.imod(f._invmp(this.m).mul(this.r2));
        return u._forceRed(this);
      };
    })(r, sc);
  })(Bi)), Bi.exports;
}
var Zi, Zn;
function Kr() {
  if (Zn) return Zi;
  Zn = 1, Zi = r;
  function r(e, t) {
    if (!e)
      throw new Error(t || "Assertion failed");
  }
  return r.equal = function(t, i, o) {
    if (t != i)
      throw new Error(o || "Assertion failed: " + t + " != " + i);
  }, Zi;
}
var Qi = {}, Qn;
function ks() {
  return Qn || (Qn = 1, (function(r) {
    var e = r;
    function t(a, p) {
      if (Array.isArray(a))
        return a.slice();
      if (!a)
        return [];
      var c = [];
      if (typeof a != "string") {
        for (var g = 0; g < a.length; g++)
          c[g] = a[g] | 0;
        return c;
      }
      if (p === "hex") {
        a = a.replace(/[^a-z0-9]+/ig, ""), a.length % 2 !== 0 && (a = "0" + a);
        for (var g = 0; g < a.length; g += 2)
          c.push(parseInt(a[g] + a[g + 1], 16));
      } else
        for (var g = 0; g < a.length; g++) {
          var h = a.charCodeAt(g), m = h >> 8, S = h & 255;
          m ? c.push(m, S) : c.push(S);
        }
      return c;
    }
    e.toArray = t;
    function i(a) {
      return a.length === 1 ? "0" + a : a;
    }
    e.zero2 = i;
    function o(a) {
      for (var p = "", c = 0; c < a.length; c++)
        p += i(a[c].toString(16));
      return p;
    }
    e.toHex = o, e.encode = function(p, c) {
      return c === "hex" ? o(p) : p;
    };
  })(Qi)), Qi;
}
var $n;
function Dt() {
  return $n || ($n = 1, (function(r) {
    var e = r, t = nr(), i = Kr(), o = ks();
    e.assert = i, e.toArray = o.toArray, e.zero2 = o.zero2, e.toHex = o.toHex, e.encode = o.encode;
    function a(m, S, M) {
      var I = new Array(Math.max(m.bitLength(), M) + 1), _;
      for (_ = 0; _ < I.length; _ += 1)
        I[_] = 0;
      var E = 1 << S + 1, O = m.clone();
      for (_ = 0; _ < I.length; _++) {
        var N, U = O.andln(E - 1);
        O.isOdd() ? (U > (E >> 1) - 1 ? N = (E >> 1) - U : N = U, O.isubn(N)) : N = 0, I[_] = N, O.iushrn(1);
      }
      return I;
    }
    e.getNAF = a;
    function p(m, S) {
      var M = [
        [],
        []
      ];
      m = m.clone(), S = S.clone();
      for (var I = 0, _ = 0, E; m.cmpn(-I) > 0 || S.cmpn(-_) > 0; ) {
        var O = m.andln(3) + I & 3, N = S.andln(3) + _ & 3;
        O === 3 && (O = -1), N === 3 && (N = -1);
        var U;
        (O & 1) === 0 ? U = 0 : (E = m.andln(7) + I & 7, (E === 3 || E === 5) && N === 2 ? U = -O : U = O), M[0].push(U);
        var j;
        (N & 1) === 0 ? j = 0 : (E = S.andln(7) + _ & 7, (E === 3 || E === 5) && O === 2 ? j = -N : j = N), M[1].push(j), 2 * I === U + 1 && (I = 1 - I), 2 * _ === j + 1 && (_ = 1 - _), m.iushrn(1), S.iushrn(1);
      }
      return M;
    }
    e.getJSF = p;
    function c(m, S, M) {
      var I = "_" + S;
      m.prototype[S] = function() {
        return this[I] !== void 0 ? this[I] : this[I] = M.call(this);
      };
    }
    e.cachedProperty = c;
    function g(m) {
      return typeof m == "string" ? e.toArray(m, "hex") : m;
    }
    e.parseBytes = g;
    function h(m) {
      return new t(m, "hex", "le");
    }
    e.intFromLE = h;
  })(Xi)), Xi;
}
var di = { exports: {} }, eo;
function Ss() {
  if (eo) return di.exports;
  eo = 1;
  var r;
  di.exports = function(o) {
    return r || (r = new e(null)), r.generate(o);
  };
  function e(i) {
    this.rand = i;
  }
  if (di.exports.Rand = e, e.prototype.generate = function(o) {
    return this._rand(o);
  }, e.prototype._rand = function(o) {
    if (this.rand.getBytes)
      return this.rand.getBytes(o);
    for (var a = new Uint8Array(o), p = 0; p < a.length; p++)
      a[p] = this.rand.getByte();
    return a;
  }, typeof self == "object")
    self.crypto && self.crypto.getRandomValues ? e.prototype._rand = function(o) {
      var a = new Uint8Array(o);
      return self.crypto.getRandomValues(a), a;
    } : self.msCrypto && self.msCrypto.getRandomValues ? e.prototype._rand = function(o) {
      var a = new Uint8Array(o);
      return self.msCrypto.getRandomValues(a), a;
    } : typeof window == "object" && (e.prototype._rand = function() {
      throw new Error("Not implemented yet");
    });
  else
    try {
      var t = an;
      if (typeof t.randomBytes != "function")
        throw new Error("Not supported");
      e.prototype._rand = function(o) {
        return t.randomBytes(o);
      };
    } catch {
    }
  return di.exports;
}
var $i = {}, ea, to;
function Ri() {
  if (to) return ea;
  to = 1;
  var r = nr(), e = Dt(), t = e.getNAF, i = e.getJSF, o = e.assert;
  function a(c, g) {
    this.type = c, this.p = new r(g.p, 16), this.red = g.prime ? r.red(g.prime) : r.mont(this.p), this.zero = new r(0).toRed(this.red), this.one = new r(1).toRed(this.red), this.two = new r(2).toRed(this.red), this.n = g.n && new r(g.n, 16), this.g = g.g && this.pointFromJSON(g.g, g.gRed), this._wnafT1 = new Array(4), this._wnafT2 = new Array(4), this._wnafT3 = new Array(4), this._wnafT4 = new Array(4), this._bitLength = this.n ? this.n.bitLength() : 0;
    var h = this.n && this.p.div(this.n);
    !h || h.cmpn(100) > 0 ? this.redN = null : (this._maxwellTrick = !0, this.redN = this.n.toRed(this.red));
  }
  ea = a, a.prototype.point = function() {
    throw new Error("Not implemented");
  }, a.prototype.validate = function() {
    throw new Error("Not implemented");
  }, a.prototype._fixedNafMul = function(g, h) {
    o(g.precomputed);
    var m = g._getDoubles(), S = t(h, 1, this._bitLength), M = (1 << m.step + 1) - (m.step % 2 === 0 ? 2 : 1);
    M /= 3;
    var I = [], _, E;
    for (_ = 0; _ < S.length; _ += m.step) {
      E = 0;
      for (var O = _ + m.step - 1; O >= _; O--)
        E = (E << 1) + S[O];
      I.push(E);
    }
    for (var N = this.jpoint(null, null, null), U = this.jpoint(null, null, null), j = M; j > 0; j--) {
      for (_ = 0; _ < I.length; _++)
        E = I[_], E === j ? U = U.mixedAdd(m.points[_]) : E === -j && (U = U.mixedAdd(m.points[_].neg()));
      N = N.add(U);
    }
    return N.toP();
  }, a.prototype._wnafMul = function(g, h) {
    var m = 4, S = g._getNAFPoints(m);
    m = S.wnd;
    for (var M = S.points, I = t(h, m, this._bitLength), _ = this.jpoint(null, null, null), E = I.length - 1; E >= 0; E--) {
      for (var O = 0; E >= 0 && I[E] === 0; E--)
        O++;
      if (E >= 0 && O++, _ = _.dblp(O), E < 0)
        break;
      var N = I[E];
      o(N !== 0), g.type === "affine" ? N > 0 ? _ = _.mixedAdd(M[N - 1 >> 1]) : _ = _.mixedAdd(M[-N - 1 >> 1].neg()) : N > 0 ? _ = _.add(M[N - 1 >> 1]) : _ = _.add(M[-N - 1 >> 1].neg());
    }
    return g.type === "affine" ? _.toP() : _;
  }, a.prototype._wnafMulAdd = function(g, h, m, S, M) {
    var I = this._wnafT1, _ = this._wnafT2, E = this._wnafT3, O = 0, N, U, j;
    for (N = 0; N < S; N++) {
      j = h[N];
      var F = j._getNAFPoints(g);
      I[N] = F.wnd, _[N] = F.points;
    }
    for (N = S - 1; N >= 1; N -= 2) {
      var C = N - 1, q = N;
      if (I[C] !== 1 || I[q] !== 1) {
        E[C] = t(m[C], I[C], this._bitLength), E[q] = t(m[q], I[q], this._bitLength), O = Math.max(E[C].length, O), O = Math.max(E[q].length, O);
        continue;
      }
      var V = [
        h[C],
        /* 1 */
        null,
        /* 3 */
        null,
        /* 5 */
        h[q]
        /* 7 */
      ];
      h[C].y.cmp(h[q].y) === 0 ? (V[1] = h[C].add(h[q]), V[2] = h[C].toJ().mixedAdd(h[q].neg())) : h[C].y.cmp(h[q].y.redNeg()) === 0 ? (V[1] = h[C].toJ().mixedAdd(h[q]), V[2] = h[C].add(h[q].neg())) : (V[1] = h[C].toJ().mixedAdd(h[q]), V[2] = h[C].toJ().mixedAdd(h[q].neg()));
      var Z = [
        -3,
        /* -1 -1 */
        -1,
        /* -1 0 */
        -5,
        /* -1 1 */
        -7,
        /* 0 -1 */
        0,
        /* 0 0 */
        7,
        /* 0 1 */
        5,
        /* 1 -1 */
        1,
        /* 1 0 */
        3
        /* 1 1 */
      ], K = i(m[C], m[q]);
      for (O = Math.max(K[0].length, O), E[C] = new Array(O), E[q] = new Array(O), U = 0; U < O; U++) {
        var G = K[0][U] | 0, z = K[1][U] | 0;
        E[C][U] = Z[(G + 1) * 3 + (z + 1)], E[q][U] = 0, _[C] = V;
      }
    }
    var f = this.jpoint(null, null, null), u = this._wnafT4;
    for (N = O; N >= 0; N--) {
      for (var n = 0; N >= 0; ) {
        var s = !0;
        for (U = 0; U < S; U++)
          u[U] = E[U][N] | 0, u[U] !== 0 && (s = !1);
        if (!s)
          break;
        n++, N--;
      }
      if (N >= 0 && n++, f = f.dblp(n), N < 0)
        break;
      for (U = 0; U < S; U++) {
        var d = u[U];
        d !== 0 && (d > 0 ? j = _[U][d - 1 >> 1] : d < 0 && (j = _[U][-d - 1 >> 1].neg()), j.type === "affine" ? f = f.mixedAdd(j) : f = f.add(j));
      }
    }
    for (N = 0; N < S; N++)
      _[N] = null;
    return M ? f : f.toP();
  };
  function p(c, g) {
    this.curve = c, this.type = g, this.precomputed = null;
  }
  return a.BasePoint = p, p.prototype.eq = function() {
    throw new Error("Not implemented");
  }, p.prototype.validate = function() {
    return this.curve.validate(this);
  }, a.prototype.decodePoint = function(g, h) {
    g = e.toArray(g, h);
    var m = this.p.byteLength();
    if ((g[0] === 4 || g[0] === 6 || g[0] === 7) && g.length - 1 === 2 * m) {
      g[0] === 6 ? o(g[g.length - 1] % 2 === 0) : g[0] === 7 && o(g[g.length - 1] % 2 === 1);
      var S = this.point(
        g.slice(1, 1 + m),
        g.slice(1 + m, 1 + 2 * m)
      );
      return S;
    } else if ((g[0] === 2 || g[0] === 3) && g.length - 1 === m)
      return this.pointFromX(g.slice(1, 1 + m), g[0] === 3);
    throw new Error("Unknown point format");
  }, p.prototype.encodeCompressed = function(g) {
    return this.encode(g, !0);
  }, p.prototype._encode = function(g) {
    var h = this.curve.p.byteLength(), m = this.getX().toArray("be", h);
    return g ? [this.getY().isEven() ? 2 : 3].concat(m) : [4].concat(m, this.getY().toArray("be", h));
  }, p.prototype.encode = function(g, h) {
    return e.encode(this._encode(h), g);
  }, p.prototype.precompute = function(g) {
    if (this.precomputed)
      return this;
    var h = {
      doubles: null,
      naf: null,
      beta: null
    };
    return h.naf = this._getNAFPoints(8), h.doubles = this._getDoubles(4, g), h.beta = this._getBeta(), this.precomputed = h, this;
  }, p.prototype._hasDoubles = function(g) {
    if (!this.precomputed)
      return !1;
    var h = this.precomputed.doubles;
    return h ? h.points.length >= Math.ceil((g.bitLength() + 1) / h.step) : !1;
  }, p.prototype._getDoubles = function(g, h) {
    if (this.precomputed && this.precomputed.doubles)
      return this.precomputed.doubles;
    for (var m = [this], S = this, M = 0; M < h; M += g) {
      for (var I = 0; I < g; I++)
        S = S.dbl();
      m.push(S);
    }
    return {
      step: g,
      points: m
    };
  }, p.prototype._getNAFPoints = function(g) {
    if (this.precomputed && this.precomputed.naf)
      return this.precomputed.naf;
    for (var h = [this], m = (1 << g) - 1, S = m === 1 ? null : this.dbl(), M = 1; M < m; M++)
      h[M] = h[M - 1].add(S);
    return {
      wnd: g,
      points: h
    };
  }, p.prototype._getBeta = function() {
    return null;
  }, p.prototype.dblp = function(g) {
    for (var h = this, m = 0; m < g; m++)
      h = h.dbl();
    return h;
  }, ea;
}
var pi = { exports: {} }, ro;
function Li() {
  return ro || (ro = 1, typeof Object.create == "function" ? pi.exports = function(e, t) {
    t && (e.super_ = t, e.prototype = Object.create(t.prototype, {
      constructor: {
        value: e,
        enumerable: !1,
        writable: !0,
        configurable: !0
      }
    }));
  } : pi.exports = function(e, t) {
    if (t) {
      e.super_ = t;
      var i = function() {
      };
      i.prototype = t.prototype, e.prototype = new i(), e.prototype.constructor = e;
    }
  }), pi.exports;
}
var ta, io;
function uc() {
  if (io) return ta;
  io = 1;
  var r = Dt(), e = nr(), t = Li(), i = Ri(), o = r.assert;
  function a(g) {
    i.call(this, "short", g), this.a = new e(g.a, 16).toRed(this.red), this.b = new e(g.b, 16).toRed(this.red), this.tinv = this.two.redInvm(), this.zeroA = this.a.fromRed().cmpn(0) === 0, this.threeA = this.a.fromRed().sub(this.p).cmpn(-3) === 0, this.endo = this._getEndomorphism(g), this._endoWnafT1 = new Array(4), this._endoWnafT2 = new Array(4);
  }
  t(a, i), ta = a, a.prototype._getEndomorphism = function(h) {
    if (!(!this.zeroA || !this.g || !this.n || this.p.modn(3) !== 1)) {
      var m, S;
      if (h.beta)
        m = new e(h.beta, 16).toRed(this.red);
      else {
        var M = this._getEndoRoots(this.p);
        m = M[0].cmp(M[1]) < 0 ? M[0] : M[1], m = m.toRed(this.red);
      }
      if (h.lambda)
        S = new e(h.lambda, 16);
      else {
        var I = this._getEndoRoots(this.n);
        this.g.mul(I[0]).x.cmp(this.g.x.redMul(m)) === 0 ? S = I[0] : (S = I[1], o(this.g.mul(S).x.cmp(this.g.x.redMul(m)) === 0));
      }
      var _;
      return h.basis ? _ = h.basis.map(function(E) {
        return {
          a: new e(E.a, 16),
          b: new e(E.b, 16)
        };
      }) : _ = this._getEndoBasis(S), {
        beta: m,
        lambda: S,
        basis: _
      };
    }
  }, a.prototype._getEndoRoots = function(h) {
    var m = h === this.p ? this.red : e.mont(h), S = new e(2).toRed(m).redInvm(), M = S.redNeg(), I = new e(3).toRed(m).redNeg().redSqrt().redMul(S), _ = M.redAdd(I).fromRed(), E = M.redSub(I).fromRed();
    return [_, E];
  }, a.prototype._getEndoBasis = function(h) {
    for (var m = this.n.ushrn(Math.floor(this.n.bitLength() / 2)), S = h, M = this.n.clone(), I = new e(1), _ = new e(0), E = new e(0), O = new e(1), N, U, j, F, C, q, V, Z = 0, K, G; S.cmpn(0) !== 0; ) {
      var z = M.div(S);
      K = M.sub(z.mul(S)), G = E.sub(z.mul(I));
      var f = O.sub(z.mul(_));
      if (!j && K.cmp(m) < 0)
        N = V.neg(), U = I, j = K.neg(), F = G;
      else if (j && ++Z === 2)
        break;
      V = K, M = S, S = K, E = I, I = G, O = _, _ = f;
    }
    C = K.neg(), q = G;
    var u = j.sqr().add(F.sqr()), n = C.sqr().add(q.sqr());
    return n.cmp(u) >= 0 && (C = N, q = U), j.negative && (j = j.neg(), F = F.neg()), C.negative && (C = C.neg(), q = q.neg()), [
      { a: j, b: F },
      { a: C, b: q }
    ];
  }, a.prototype._endoSplit = function(h) {
    var m = this.endo.basis, S = m[0], M = m[1], I = M.b.mul(h).divRound(this.n), _ = S.b.neg().mul(h).divRound(this.n), E = I.mul(S.a), O = _.mul(M.a), N = I.mul(S.b), U = _.mul(M.b), j = h.sub(E).sub(O), F = N.add(U).neg();
    return { k1: j, k2: F };
  }, a.prototype.pointFromX = function(h, m) {
    h = new e(h, 16), h.red || (h = h.toRed(this.red));
    var S = h.redSqr().redMul(h).redIAdd(h.redMul(this.a)).redIAdd(this.b), M = S.redSqrt();
    if (M.redSqr().redSub(S).cmp(this.zero) !== 0)
      throw new Error("invalid point");
    var I = M.fromRed().isOdd();
    return (m && !I || !m && I) && (M = M.redNeg()), this.point(h, M);
  }, a.prototype.validate = function(h) {
    if (h.inf)
      return !0;
    var m = h.x, S = h.y, M = this.a.redMul(m), I = m.redSqr().redMul(m).redIAdd(M).redIAdd(this.b);
    return S.redSqr().redISub(I).cmpn(0) === 0;
  }, a.prototype._endoWnafMulAdd = function(h, m, S) {
    for (var M = this._endoWnafT1, I = this._endoWnafT2, _ = 0; _ < h.length; _++) {
      var E = this._endoSplit(m[_]), O = h[_], N = O._getBeta();
      E.k1.negative && (E.k1.ineg(), O = O.neg(!0)), E.k2.negative && (E.k2.ineg(), N = N.neg(!0)), M[_ * 2] = O, M[_ * 2 + 1] = N, I[_ * 2] = E.k1, I[_ * 2 + 1] = E.k2;
    }
    for (var U = this._wnafMulAdd(1, M, I, _ * 2, S), j = 0; j < _ * 2; j++)
      M[j] = null, I[j] = null;
    return U;
  };
  function p(g, h, m, S) {
    i.BasePoint.call(this, g, "affine"), h === null && m === null ? (this.x = null, this.y = null, this.inf = !0) : (this.x = new e(h, 16), this.y = new e(m, 16), S && (this.x.forceRed(this.curve.red), this.y.forceRed(this.curve.red)), this.x.red || (this.x = this.x.toRed(this.curve.red)), this.y.red || (this.y = this.y.toRed(this.curve.red)), this.inf = !1);
  }
  t(p, i.BasePoint), a.prototype.point = function(h, m, S) {
    return new p(this, h, m, S);
  }, a.prototype.pointFromJSON = function(h, m) {
    return p.fromJSON(this, h, m);
  }, p.prototype._getBeta = function() {
    if (this.curve.endo) {
      var h = this.precomputed;
      if (h && h.beta)
        return h.beta;
      var m = this.curve.point(this.x.redMul(this.curve.endo.beta), this.y);
      if (h) {
        var S = this.curve, M = function(I) {
          return S.point(I.x.redMul(S.endo.beta), I.y);
        };
        h.beta = m, m.precomputed = {
          beta: null,
          naf: h.naf && {
            wnd: h.naf.wnd,
            points: h.naf.points.map(M)
          },
          doubles: h.doubles && {
            step: h.doubles.step,
            points: h.doubles.points.map(M)
          }
        };
      }
      return m;
    }
  }, p.prototype.toJSON = function() {
    return this.precomputed ? [this.x, this.y, this.precomputed && {
      doubles: this.precomputed.doubles && {
        step: this.precomputed.doubles.step,
        points: this.precomputed.doubles.points.slice(1)
      },
      naf: this.precomputed.naf && {
        wnd: this.precomputed.naf.wnd,
        points: this.precomputed.naf.points.slice(1)
      }
    }] : [this.x, this.y];
  }, p.fromJSON = function(h, m, S) {
    typeof m == "string" && (m = JSON.parse(m));
    var M = h.point(m[0], m[1], S);
    if (!m[2])
      return M;
    function I(E) {
      return h.point(E[0], E[1], S);
    }
    var _ = m[2];
    return M.precomputed = {
      beta: null,
      doubles: _.doubles && {
        step: _.doubles.step,
        points: [M].concat(_.doubles.points.map(I))
      },
      naf: _.naf && {
        wnd: _.naf.wnd,
        points: [M].concat(_.naf.points.map(I))
      }
    }, M;
  }, p.prototype.inspect = function() {
    return this.isInfinity() ? "<EC Point Infinity>" : "<EC Point x: " + this.x.fromRed().toString(16, 2) + " y: " + this.y.fromRed().toString(16, 2) + ">";
  }, p.prototype.isInfinity = function() {
    return this.inf;
  }, p.prototype.add = function(h) {
    if (this.inf)
      return h;
    if (h.inf)
      return this;
    if (this.eq(h))
      return this.dbl();
    if (this.neg().eq(h))
      return this.curve.point(null, null);
    if (this.x.cmp(h.x) === 0)
      return this.curve.point(null, null);
    var m = this.y.redSub(h.y);
    m.cmpn(0) !== 0 && (m = m.redMul(this.x.redSub(h.x).redInvm()));
    var S = m.redSqr().redISub(this.x).redISub(h.x), M = m.redMul(this.x.redSub(S)).redISub(this.y);
    return this.curve.point(S, M);
  }, p.prototype.dbl = function() {
    if (this.inf)
      return this;
    var h = this.y.redAdd(this.y);
    if (h.cmpn(0) === 0)
      return this.curve.point(null, null);
    var m = this.curve.a, S = this.x.redSqr(), M = h.redInvm(), I = S.redAdd(S).redIAdd(S).redIAdd(m).redMul(M), _ = I.redSqr().redISub(this.x.redAdd(this.x)), E = I.redMul(this.x.redSub(_)).redISub(this.y);
    return this.curve.point(_, E);
  }, p.prototype.getX = function() {
    return this.x.fromRed();
  }, p.prototype.getY = function() {
    return this.y.fromRed();
  }, p.prototype.mul = function(h) {
    return h = new e(h, 16), this.isInfinity() ? this : this._hasDoubles(h) ? this.curve._fixedNafMul(this, h) : this.curve.endo ? this.curve._endoWnafMulAdd([this], [h]) : this.curve._wnafMul(this, h);
  }, p.prototype.mulAdd = function(h, m, S) {
    var M = [this, m], I = [h, S];
    return this.curve.endo ? this.curve._endoWnafMulAdd(M, I) : this.curve._wnafMulAdd(1, M, I, 2);
  }, p.prototype.jmulAdd = function(h, m, S) {
    var M = [this, m], I = [h, S];
    return this.curve.endo ? this.curve._endoWnafMulAdd(M, I, !0) : this.curve._wnafMulAdd(1, M, I, 2, !0);
  }, p.prototype.eq = function(h) {
    return this === h || this.inf === h.inf && (this.inf || this.x.cmp(h.x) === 0 && this.y.cmp(h.y) === 0);
  }, p.prototype.neg = function(h) {
    if (this.inf)
      return this;
    var m = this.curve.point(this.x, this.y.redNeg());
    if (h && this.precomputed) {
      var S = this.precomputed, M = function(I) {
        return I.neg();
      };
      m.precomputed = {
        naf: S.naf && {
          wnd: S.naf.wnd,
          points: S.naf.points.map(M)
        },
        doubles: S.doubles && {
          step: S.doubles.step,
          points: S.doubles.points.map(M)
        }
      };
    }
    return m;
  }, p.prototype.toJ = function() {
    if (this.inf)
      return this.curve.jpoint(null, null, null);
    var h = this.curve.jpoint(this.x, this.y, this.curve.one);
    return h;
  };
  function c(g, h, m, S) {
    i.BasePoint.call(this, g, "jacobian"), h === null && m === null && S === null ? (this.x = this.curve.one, this.y = this.curve.one, this.z = new e(0)) : (this.x = new e(h, 16), this.y = new e(m, 16), this.z = new e(S, 16)), this.x.red || (this.x = this.x.toRed(this.curve.red)), this.y.red || (this.y = this.y.toRed(this.curve.red)), this.z.red || (this.z = this.z.toRed(this.curve.red)), this.zOne = this.z === this.curve.one;
  }
  return t(c, i.BasePoint), a.prototype.jpoint = function(h, m, S) {
    return new c(this, h, m, S);
  }, c.prototype.toP = function() {
    if (this.isInfinity())
      return this.curve.point(null, null);
    var h = this.z.redInvm(), m = h.redSqr(), S = this.x.redMul(m), M = this.y.redMul(m).redMul(h);
    return this.curve.point(S, M);
  }, c.prototype.neg = function() {
    return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
  }, c.prototype.add = function(h) {
    if (this.isInfinity())
      return h;
    if (h.isInfinity())
      return this;
    var m = h.z.redSqr(), S = this.z.redSqr(), M = this.x.redMul(m), I = h.x.redMul(S), _ = this.y.redMul(m.redMul(h.z)), E = h.y.redMul(S.redMul(this.z)), O = M.redSub(I), N = _.redSub(E);
    if (O.cmpn(0) === 0)
      return N.cmpn(0) !== 0 ? this.curve.jpoint(null, null, null) : this.dbl();
    var U = O.redSqr(), j = U.redMul(O), F = M.redMul(U), C = N.redSqr().redIAdd(j).redISub(F).redISub(F), q = N.redMul(F.redISub(C)).redISub(_.redMul(j)), V = this.z.redMul(h.z).redMul(O);
    return this.curve.jpoint(C, q, V);
  }, c.prototype.mixedAdd = function(h) {
    if (this.isInfinity())
      return h.toJ();
    if (h.isInfinity())
      return this;
    var m = this.z.redSqr(), S = this.x, M = h.x.redMul(m), I = this.y, _ = h.y.redMul(m).redMul(this.z), E = S.redSub(M), O = I.redSub(_);
    if (E.cmpn(0) === 0)
      return O.cmpn(0) !== 0 ? this.curve.jpoint(null, null, null) : this.dbl();
    var N = E.redSqr(), U = N.redMul(E), j = S.redMul(N), F = O.redSqr().redIAdd(U).redISub(j).redISub(j), C = O.redMul(j.redISub(F)).redISub(I.redMul(U)), q = this.z.redMul(E);
    return this.curve.jpoint(F, C, q);
  }, c.prototype.dblp = function(h) {
    if (h === 0)
      return this;
    if (this.isInfinity())
      return this;
    if (!h)
      return this.dbl();
    var m;
    if (this.curve.zeroA || this.curve.threeA) {
      var S = this;
      for (m = 0; m < h; m++)
        S = S.dbl();
      return S;
    }
    var M = this.curve.a, I = this.curve.tinv, _ = this.x, E = this.y, O = this.z, N = O.redSqr().redSqr(), U = E.redAdd(E);
    for (m = 0; m < h; m++) {
      var j = _.redSqr(), F = U.redSqr(), C = F.redSqr(), q = j.redAdd(j).redIAdd(j).redIAdd(M.redMul(N)), V = _.redMul(F), Z = q.redSqr().redISub(V.redAdd(V)), K = V.redISub(Z), G = q.redMul(K);
      G = G.redIAdd(G).redISub(C);
      var z = U.redMul(O);
      m + 1 < h && (N = N.redMul(C)), _ = Z, O = z, U = G;
    }
    return this.curve.jpoint(_, U.redMul(I), O);
  }, c.prototype.dbl = function() {
    return this.isInfinity() ? this : this.curve.zeroA ? this._zeroDbl() : this.curve.threeA ? this._threeDbl() : this._dbl();
  }, c.prototype._zeroDbl = function() {
    var h, m, S;
    if (this.zOne) {
      var M = this.x.redSqr(), I = this.y.redSqr(), _ = I.redSqr(), E = this.x.redAdd(I).redSqr().redISub(M).redISub(_);
      E = E.redIAdd(E);
      var O = M.redAdd(M).redIAdd(M), N = O.redSqr().redISub(E).redISub(E), U = _.redIAdd(_);
      U = U.redIAdd(U), U = U.redIAdd(U), h = N, m = O.redMul(E.redISub(N)).redISub(U), S = this.y.redAdd(this.y);
    } else {
      var j = this.x.redSqr(), F = this.y.redSqr(), C = F.redSqr(), q = this.x.redAdd(F).redSqr().redISub(j).redISub(C);
      q = q.redIAdd(q);
      var V = j.redAdd(j).redIAdd(j), Z = V.redSqr(), K = C.redIAdd(C);
      K = K.redIAdd(K), K = K.redIAdd(K), h = Z.redISub(q).redISub(q), m = V.redMul(q.redISub(h)).redISub(K), S = this.y.redMul(this.z), S = S.redIAdd(S);
    }
    return this.curve.jpoint(h, m, S);
  }, c.prototype._threeDbl = function() {
    var h, m, S;
    if (this.zOne) {
      var M = this.x.redSqr(), I = this.y.redSqr(), _ = I.redSqr(), E = this.x.redAdd(I).redSqr().redISub(M).redISub(_);
      E = E.redIAdd(E);
      var O = M.redAdd(M).redIAdd(M).redIAdd(this.curve.a), N = O.redSqr().redISub(E).redISub(E);
      h = N;
      var U = _.redIAdd(_);
      U = U.redIAdd(U), U = U.redIAdd(U), m = O.redMul(E.redISub(N)).redISub(U), S = this.y.redAdd(this.y);
    } else {
      var j = this.z.redSqr(), F = this.y.redSqr(), C = this.x.redMul(F), q = this.x.redSub(j).redMul(this.x.redAdd(j));
      q = q.redAdd(q).redIAdd(q);
      var V = C.redIAdd(C);
      V = V.redIAdd(V);
      var Z = V.redAdd(V);
      h = q.redSqr().redISub(Z), S = this.y.redAdd(this.z).redSqr().redISub(F).redISub(j);
      var K = F.redSqr();
      K = K.redIAdd(K), K = K.redIAdd(K), K = K.redIAdd(K), m = q.redMul(V.redISub(h)).redISub(K);
    }
    return this.curve.jpoint(h, m, S);
  }, c.prototype._dbl = function() {
    var h = this.curve.a, m = this.x, S = this.y, M = this.z, I = M.redSqr().redSqr(), _ = m.redSqr(), E = S.redSqr(), O = _.redAdd(_).redIAdd(_).redIAdd(h.redMul(I)), N = m.redAdd(m);
    N = N.redIAdd(N);
    var U = N.redMul(E), j = O.redSqr().redISub(U.redAdd(U)), F = U.redISub(j), C = E.redSqr();
    C = C.redIAdd(C), C = C.redIAdd(C), C = C.redIAdd(C);
    var q = O.redMul(F).redISub(C), V = S.redAdd(S).redMul(M);
    return this.curve.jpoint(j, q, V);
  }, c.prototype.trpl = function() {
    if (!this.curve.zeroA)
      return this.dbl().add(this);
    var h = this.x.redSqr(), m = this.y.redSqr(), S = this.z.redSqr(), M = m.redSqr(), I = h.redAdd(h).redIAdd(h), _ = I.redSqr(), E = this.x.redAdd(m).redSqr().redISub(h).redISub(M);
    E = E.redIAdd(E), E = E.redAdd(E).redIAdd(E), E = E.redISub(_);
    var O = E.redSqr(), N = M.redIAdd(M);
    N = N.redIAdd(N), N = N.redIAdd(N), N = N.redIAdd(N);
    var U = I.redIAdd(E).redSqr().redISub(_).redISub(O).redISub(N), j = m.redMul(U);
    j = j.redIAdd(j), j = j.redIAdd(j);
    var F = this.x.redMul(O).redISub(j);
    F = F.redIAdd(F), F = F.redIAdd(F);
    var C = this.y.redMul(U.redMul(N.redISub(U)).redISub(E.redMul(O)));
    C = C.redIAdd(C), C = C.redIAdd(C), C = C.redIAdd(C);
    var q = this.z.redAdd(E).redSqr().redISub(S).redISub(O);
    return this.curve.jpoint(F, C, q);
  }, c.prototype.mul = function(h, m) {
    return h = new e(h, m), this.curve._wnafMul(this, h);
  }, c.prototype.eq = function(h) {
    if (h.type === "affine")
      return this.eq(h.toJ());
    if (this === h)
      return !0;
    var m = this.z.redSqr(), S = h.z.redSqr();
    if (this.x.redMul(S).redISub(h.x.redMul(m)).cmpn(0) !== 0)
      return !1;
    var M = m.redMul(this.z), I = S.redMul(h.z);
    return this.y.redMul(I).redISub(h.y.redMul(M)).cmpn(0) === 0;
  }, c.prototype.eqXToP = function(h) {
    var m = this.z.redSqr(), S = h.toRed(this.curve.red).redMul(m);
    if (this.x.cmp(S) === 0)
      return !0;
    for (var M = h.clone(), I = this.curve.redN.redMul(m); ; ) {
      if (M.iadd(this.curve.n), M.cmp(this.curve.p) >= 0)
        return !1;
      if (S.redIAdd(I), this.x.cmp(S) === 0)
        return !0;
    }
  }, c.prototype.inspect = function() {
    return this.isInfinity() ? "<EC JPoint Infinity>" : "<EC JPoint x: " + this.x.toString(16, 2) + " y: " + this.y.toString(16, 2) + " z: " + this.z.toString(16, 2) + ">";
  }, c.prototype.isInfinity = function() {
    return this.z.cmpn(0) === 0;
  }, ta;
}
var ra, ao;
function fc() {
  if (ao) return ra;
  ao = 1;
  var r = nr(), e = Li(), t = Ri(), i = Dt();
  function o(p) {
    t.call(this, "mont", p), this.a = new r(p.a, 16).toRed(this.red), this.b = new r(p.b, 16).toRed(this.red), this.i4 = new r(4).toRed(this.red).redInvm(), this.two = new r(2).toRed(this.red), this.a24 = this.i4.redMul(this.a.redAdd(this.two));
  }
  e(o, t), ra = o, o.prototype.validate = function(c) {
    var g = c.normalize().x, h = g.redSqr(), m = h.redMul(g).redAdd(h.redMul(this.a)).redAdd(g), S = m.redSqrt();
    return S.redSqr().cmp(m) === 0;
  };
  function a(p, c, g) {
    t.BasePoint.call(this, p, "projective"), c === null && g === null ? (this.x = this.curve.one, this.z = this.curve.zero) : (this.x = new r(c, 16), this.z = new r(g, 16), this.x.red || (this.x = this.x.toRed(this.curve.red)), this.z.red || (this.z = this.z.toRed(this.curve.red)));
  }
  return e(a, t.BasePoint), o.prototype.decodePoint = function(c, g) {
    return this.point(i.toArray(c, g), 1);
  }, o.prototype.point = function(c, g) {
    return new a(this, c, g);
  }, o.prototype.pointFromJSON = function(c) {
    return a.fromJSON(this, c);
  }, a.prototype.precompute = function() {
  }, a.prototype._encode = function() {
    return this.getX().toArray("be", this.curve.p.byteLength());
  }, a.fromJSON = function(c, g) {
    return new a(c, g[0], g[1] || c.one);
  }, a.prototype.inspect = function() {
    return this.isInfinity() ? "<EC Point Infinity>" : "<EC Point x: " + this.x.fromRed().toString(16, 2) + " z: " + this.z.fromRed().toString(16, 2) + ">";
  }, a.prototype.isInfinity = function() {
    return this.z.cmpn(0) === 0;
  }, a.prototype.dbl = function() {
    var c = this.x.redAdd(this.z), g = c.redSqr(), h = this.x.redSub(this.z), m = h.redSqr(), S = g.redSub(m), M = g.redMul(m), I = S.redMul(m.redAdd(this.curve.a24.redMul(S)));
    return this.curve.point(M, I);
  }, a.prototype.add = function() {
    throw new Error("Not supported on Montgomery curve");
  }, a.prototype.diffAdd = function(c, g) {
    var h = this.x.redAdd(this.z), m = this.x.redSub(this.z), S = c.x.redAdd(c.z), M = c.x.redSub(c.z), I = M.redMul(h), _ = S.redMul(m), E = g.z.redMul(I.redAdd(_).redSqr()), O = g.x.redMul(I.redISub(_).redSqr());
    return this.curve.point(E, O);
  }, a.prototype.mul = function(c) {
    for (var g = c.clone(), h = this, m = this.curve.point(null, null), S = this, M = []; g.cmpn(0) !== 0; g.iushrn(1))
      M.push(g.andln(1));
    for (var I = M.length - 1; I >= 0; I--)
      M[I] === 0 ? (h = h.diffAdd(m, S), m = m.dbl()) : (m = h.diffAdd(m, S), h = h.dbl());
    return m;
  }, a.prototype.mulAdd = function() {
    throw new Error("Not supported on Montgomery curve");
  }, a.prototype.jumlAdd = function() {
    throw new Error("Not supported on Montgomery curve");
  }, a.prototype.eq = function(c) {
    return this.getX().cmp(c.getX()) === 0;
  }, a.prototype.normalize = function() {
    return this.x = this.x.redMul(this.z.redInvm()), this.z = this.curve.one, this;
  }, a.prototype.getX = function() {
    return this.normalize(), this.x.fromRed();
  }, ra;
}
var ia, no;
function cc() {
  if (no) return ia;
  no = 1;
  var r = Dt(), e = nr(), t = Li(), i = Ri(), o = r.assert;
  function a(c) {
    this.twisted = (c.a | 0) !== 1, this.mOneA = this.twisted && (c.a | 0) === -1, this.extended = this.mOneA, i.call(this, "edwards", c), this.a = new e(c.a, 16).umod(this.red.m), this.a = this.a.toRed(this.red), this.c = new e(c.c, 16).toRed(this.red), this.c2 = this.c.redSqr(), this.d = new e(c.d, 16).toRed(this.red), this.dd = this.d.redAdd(this.d), o(!this.twisted || this.c.fromRed().cmpn(1) === 0), this.oneC = (c.c | 0) === 1;
  }
  t(a, i), ia = a, a.prototype._mulA = function(g) {
    return this.mOneA ? g.redNeg() : this.a.redMul(g);
  }, a.prototype._mulC = function(g) {
    return this.oneC ? g : this.c.redMul(g);
  }, a.prototype.jpoint = function(g, h, m, S) {
    return this.point(g, h, m, S);
  }, a.prototype.pointFromX = function(g, h) {
    g = new e(g, 16), g.red || (g = g.toRed(this.red));
    var m = g.redSqr(), S = this.c2.redSub(this.a.redMul(m)), M = this.one.redSub(this.c2.redMul(this.d).redMul(m)), I = S.redMul(M.redInvm()), _ = I.redSqrt();
    if (_.redSqr().redSub(I).cmp(this.zero) !== 0)
      throw new Error("invalid point");
    var E = _.fromRed().isOdd();
    return (h && !E || !h && E) && (_ = _.redNeg()), this.point(g, _);
  }, a.prototype.pointFromY = function(g, h) {
    g = new e(g, 16), g.red || (g = g.toRed(this.red));
    var m = g.redSqr(), S = m.redSub(this.c2), M = m.redMul(this.d).redMul(this.c2).redSub(this.a), I = S.redMul(M.redInvm());
    if (I.cmp(this.zero) === 0) {
      if (h)
        throw new Error("invalid point");
      return this.point(this.zero, g);
    }
    var _ = I.redSqrt();
    if (_.redSqr().redSub(I).cmp(this.zero) !== 0)
      throw new Error("invalid point");
    return _.fromRed().isOdd() !== h && (_ = _.redNeg()), this.point(_, g);
  }, a.prototype.validate = function(g) {
    if (g.isInfinity())
      return !0;
    g.normalize();
    var h = g.x.redSqr(), m = g.y.redSqr(), S = h.redMul(this.a).redAdd(m), M = this.c2.redMul(this.one.redAdd(this.d.redMul(h).redMul(m)));
    return S.cmp(M) === 0;
  };
  function p(c, g, h, m, S) {
    i.BasePoint.call(this, c, "projective"), g === null && h === null && m === null ? (this.x = this.curve.zero, this.y = this.curve.one, this.z = this.curve.one, this.t = this.curve.zero, this.zOne = !0) : (this.x = new e(g, 16), this.y = new e(h, 16), this.z = m ? new e(m, 16) : this.curve.one, this.t = S && new e(S, 16), this.x.red || (this.x = this.x.toRed(this.curve.red)), this.y.red || (this.y = this.y.toRed(this.curve.red)), this.z.red || (this.z = this.z.toRed(this.curve.red)), this.t && !this.t.red && (this.t = this.t.toRed(this.curve.red)), this.zOne = this.z === this.curve.one, this.curve.extended && !this.t && (this.t = this.x.redMul(this.y), this.zOne || (this.t = this.t.redMul(this.z.redInvm()))));
  }
  return t(p, i.BasePoint), a.prototype.pointFromJSON = function(g) {
    return p.fromJSON(this, g);
  }, a.prototype.point = function(g, h, m, S) {
    return new p(this, g, h, m, S);
  }, p.fromJSON = function(g, h) {
    return new p(g, h[0], h[1], h[2]);
  }, p.prototype.inspect = function() {
    return this.isInfinity() ? "<EC Point Infinity>" : "<EC Point x: " + this.x.fromRed().toString(16, 2) + " y: " + this.y.fromRed().toString(16, 2) + " z: " + this.z.fromRed().toString(16, 2) + ">";
  }, p.prototype.isInfinity = function() {
    return this.x.cmpn(0) === 0 && (this.y.cmp(this.z) === 0 || this.zOne && this.y.cmp(this.curve.c) === 0);
  }, p.prototype._extDbl = function() {
    var g = this.x.redSqr(), h = this.y.redSqr(), m = this.z.redSqr();
    m = m.redIAdd(m);
    var S = this.curve._mulA(g), M = this.x.redAdd(this.y).redSqr().redISub(g).redISub(h), I = S.redAdd(h), _ = I.redSub(m), E = S.redSub(h), O = M.redMul(_), N = I.redMul(E), U = M.redMul(E), j = _.redMul(I);
    return this.curve.point(O, N, j, U);
  }, p.prototype._projDbl = function() {
    var g = this.x.redAdd(this.y).redSqr(), h = this.x.redSqr(), m = this.y.redSqr(), S, M, I, _, E, O;
    if (this.curve.twisted) {
      _ = this.curve._mulA(h);
      var N = _.redAdd(m);
      this.zOne ? (S = g.redSub(h).redSub(m).redMul(N.redSub(this.curve.two)), M = N.redMul(_.redSub(m)), I = N.redSqr().redSub(N).redSub(N)) : (E = this.z.redSqr(), O = N.redSub(E).redISub(E), S = g.redSub(h).redISub(m).redMul(O), M = N.redMul(_.redSub(m)), I = N.redMul(O));
    } else
      _ = h.redAdd(m), E = this.curve._mulC(this.z).redSqr(), O = _.redSub(E).redSub(E), S = this.curve._mulC(g.redISub(_)).redMul(O), M = this.curve._mulC(_).redMul(h.redISub(m)), I = _.redMul(O);
    return this.curve.point(S, M, I);
  }, p.prototype.dbl = function() {
    return this.isInfinity() ? this : this.curve.extended ? this._extDbl() : this._projDbl();
  }, p.prototype._extAdd = function(g) {
    var h = this.y.redSub(this.x).redMul(g.y.redSub(g.x)), m = this.y.redAdd(this.x).redMul(g.y.redAdd(g.x)), S = this.t.redMul(this.curve.dd).redMul(g.t), M = this.z.redMul(g.z.redAdd(g.z)), I = m.redSub(h), _ = M.redSub(S), E = M.redAdd(S), O = m.redAdd(h), N = I.redMul(_), U = E.redMul(O), j = I.redMul(O), F = _.redMul(E);
    return this.curve.point(N, U, F, j);
  }, p.prototype._projAdd = function(g) {
    var h = this.z.redMul(g.z), m = h.redSqr(), S = this.x.redMul(g.x), M = this.y.redMul(g.y), I = this.curve.d.redMul(S).redMul(M), _ = m.redSub(I), E = m.redAdd(I), O = this.x.redAdd(this.y).redMul(g.x.redAdd(g.y)).redISub(S).redISub(M), N = h.redMul(_).redMul(O), U, j;
    return this.curve.twisted ? (U = h.redMul(E).redMul(M.redSub(this.curve._mulA(S))), j = _.redMul(E)) : (U = h.redMul(E).redMul(M.redSub(S)), j = this.curve._mulC(_).redMul(E)), this.curve.point(N, U, j);
  }, p.prototype.add = function(g) {
    return this.isInfinity() ? g : g.isInfinity() ? this : this.curve.extended ? this._extAdd(g) : this._projAdd(g);
  }, p.prototype.mul = function(g) {
    return this._hasDoubles(g) ? this.curve._fixedNafMul(this, g) : this.curve._wnafMul(this, g);
  }, p.prototype.mulAdd = function(g, h, m) {
    return this.curve._wnafMulAdd(1, [this, h], [g, m], 2, !1);
  }, p.prototype.jmulAdd = function(g, h, m) {
    return this.curve._wnafMulAdd(1, [this, h], [g, m], 2, !0);
  }, p.prototype.normalize = function() {
    if (this.zOne)
      return this;
    var g = this.z.redInvm();
    return this.x = this.x.redMul(g), this.y = this.y.redMul(g), this.t && (this.t = this.t.redMul(g)), this.z = this.curve.one, this.zOne = !0, this;
  }, p.prototype.neg = function() {
    return this.curve.point(
      this.x.redNeg(),
      this.y,
      this.z,
      this.t && this.t.redNeg()
    );
  }, p.prototype.getX = function() {
    return this.normalize(), this.x.fromRed();
  }, p.prototype.getY = function() {
    return this.normalize(), this.y.fromRed();
  }, p.prototype.eq = function(g) {
    return this === g || this.getX().cmp(g.getX()) === 0 && this.getY().cmp(g.getY()) === 0;
  }, p.prototype.eqXToP = function(g) {
    var h = g.toRed(this.curve.red).redMul(this.z);
    if (this.x.cmp(h) === 0)
      return !0;
    for (var m = g.clone(), S = this.curve.redN.redMul(this.z); ; ) {
      if (m.iadd(this.curve.n), m.cmp(this.curve.p) >= 0)
        return !1;
      if (h.redIAdd(S), this.x.cmp(h) === 0)
        return !0;
    }
  }, p.prototype.toP = p.prototype.normalize, p.prototype.mixedAdd = p.prototype.add, ia;
}
var oo;
function As() {
  return oo || (oo = 1, (function(r) {
    var e = r;
    e.base = Ri(), e.short = uc(), e.mont = fc(), e.edwards = cc();
  })($i)), $i;
}
var aa = {}, na = {}, Ge = {}, so;
function Xt() {
  if (so) return Ge;
  so = 1;
  var r = Kr(), e = Li();
  Ge.inherits = e;
  function t(f, u) {
    return (f.charCodeAt(u) & 64512) !== 55296 || u < 0 || u + 1 >= f.length ? !1 : (f.charCodeAt(u + 1) & 64512) === 56320;
  }
  function i(f, u) {
    if (Array.isArray(f))
      return f.slice();
    if (!f)
      return [];
    var n = [];
    if (typeof f == "string")
      if (u) {
        if (u === "hex")
          for (f = f.replace(/[^a-z0-9]+/ig, ""), f.length % 2 !== 0 && (f = "0" + f), d = 0; d < f.length; d += 2)
            n.push(parseInt(f[d] + f[d + 1], 16));
      } else for (var s = 0, d = 0; d < f.length; d++) {
        var w = f.charCodeAt(d);
        w < 128 ? n[s++] = w : w < 2048 ? (n[s++] = w >> 6 | 192, n[s++] = w & 63 | 128) : t(f, d) ? (w = 65536 + ((w & 1023) << 10) + (f.charCodeAt(++d) & 1023), n[s++] = w >> 18 | 240, n[s++] = w >> 12 & 63 | 128, n[s++] = w >> 6 & 63 | 128, n[s++] = w & 63 | 128) : (n[s++] = w >> 12 | 224, n[s++] = w >> 6 & 63 | 128, n[s++] = w & 63 | 128);
      }
    else
      for (d = 0; d < f.length; d++)
        n[d] = f[d] | 0;
    return n;
  }
  Ge.toArray = i;
  function o(f) {
    for (var u = "", n = 0; n < f.length; n++)
      u += c(f[n].toString(16));
    return u;
  }
  Ge.toHex = o;
  function a(f) {
    var u = f >>> 24 | f >>> 8 & 65280 | f << 8 & 16711680 | (f & 255) << 24;
    return u >>> 0;
  }
  Ge.htonl = a;
  function p(f, u) {
    for (var n = "", s = 0; s < f.length; s++) {
      var d = f[s];
      u === "little" && (d = a(d)), n += g(d.toString(16));
    }
    return n;
  }
  Ge.toHex32 = p;
  function c(f) {
    return f.length === 1 ? "0" + f : f;
  }
  Ge.zero2 = c;
  function g(f) {
    return f.length === 7 ? "0" + f : f.length === 6 ? "00" + f : f.length === 5 ? "000" + f : f.length === 4 ? "0000" + f : f.length === 3 ? "00000" + f : f.length === 2 ? "000000" + f : f.length === 1 ? "0000000" + f : f;
  }
  Ge.zero8 = g;
  function h(f, u, n, s) {
    var d = n - u;
    r(d % 4 === 0);
    for (var w = new Array(d / 4), A = 0, k = u; A < w.length; A++, k += 4) {
      var l;
      s === "big" ? l = f[k] << 24 | f[k + 1] << 16 | f[k + 2] << 8 | f[k + 3] : l = f[k + 3] << 24 | f[k + 2] << 16 | f[k + 1] << 8 | f[k], w[A] = l >>> 0;
    }
    return w;
  }
  Ge.join32 = h;
  function m(f, u) {
    for (var n = new Array(f.length * 4), s = 0, d = 0; s < f.length; s++, d += 4) {
      var w = f[s];
      u === "big" ? (n[d] = w >>> 24, n[d + 1] = w >>> 16 & 255, n[d + 2] = w >>> 8 & 255, n[d + 3] = w & 255) : (n[d + 3] = w >>> 24, n[d + 2] = w >>> 16 & 255, n[d + 1] = w >>> 8 & 255, n[d] = w & 255);
    }
    return n;
  }
  Ge.split32 = m;
  function S(f, u) {
    return f >>> u | f << 32 - u;
  }
  Ge.rotr32 = S;
  function M(f, u) {
    return f << u | f >>> 32 - u;
  }
  Ge.rotl32 = M;
  function I(f, u) {
    return f + u >>> 0;
  }
  Ge.sum32 = I;
  function _(f, u, n) {
    return f + u + n >>> 0;
  }
  Ge.sum32_3 = _;
  function E(f, u, n, s) {
    return f + u + n + s >>> 0;
  }
  Ge.sum32_4 = E;
  function O(f, u, n, s, d) {
    return f + u + n + s + d >>> 0;
  }
  Ge.sum32_5 = O;
  function N(f, u, n, s) {
    var d = f[u], w = f[u + 1], A = s + w >>> 0, k = (A < s ? 1 : 0) + n + d;
    f[u] = k >>> 0, f[u + 1] = A;
  }
  Ge.sum64 = N;
  function U(f, u, n, s) {
    var d = u + s >>> 0, w = (d < u ? 1 : 0) + f + n;
    return w >>> 0;
  }
  Ge.sum64_hi = U;
  function j(f, u, n, s) {
    var d = u + s;
    return d >>> 0;
  }
  Ge.sum64_lo = j;
  function F(f, u, n, s, d, w, A, k) {
    var l = 0, y = u;
    y = y + s >>> 0, l += y < u ? 1 : 0, y = y + w >>> 0, l += y < w ? 1 : 0, y = y + k >>> 0, l += y < k ? 1 : 0;
    var v = f + n + d + A + l;
    return v >>> 0;
  }
  Ge.sum64_4_hi = F;
  function C(f, u, n, s, d, w, A, k) {
    var l = u + s + w + k;
    return l >>> 0;
  }
  Ge.sum64_4_lo = C;
  function q(f, u, n, s, d, w, A, k, l, y) {
    var v = 0, P = u;
    P = P + s >>> 0, v += P < u ? 1 : 0, P = P + w >>> 0, v += P < w ? 1 : 0, P = P + k >>> 0, v += P < k ? 1 : 0, P = P + y >>> 0, v += P < y ? 1 : 0;
    var J = f + n + d + A + l + v;
    return J >>> 0;
  }
  Ge.sum64_5_hi = q;
  function V(f, u, n, s, d, w, A, k, l, y) {
    var v = u + s + w + k + y;
    return v >>> 0;
  }
  Ge.sum64_5_lo = V;
  function Z(f, u, n) {
    var s = u << 32 - n | f >>> n;
    return s >>> 0;
  }
  Ge.rotr64_hi = Z;
  function K(f, u, n) {
    var s = f << 32 - n | u >>> n;
    return s >>> 0;
  }
  Ge.rotr64_lo = K;
  function G(f, u, n) {
    return f >>> n;
  }
  Ge.shr64_hi = G;
  function z(f, u, n) {
    var s = f << 32 - n | u >>> n;
    return s >>> 0;
  }
  return Ge.shr64_lo = z, Ge;
}
var oa = {}, uo;
function ci() {
  if (uo) return oa;
  uo = 1;
  var r = Xt(), e = Kr();
  function t() {
    this.pending = null, this.pendingTotal = 0, this.blockSize = this.constructor.blockSize, this.outSize = this.constructor.outSize, this.hmacStrength = this.constructor.hmacStrength, this.padLength = this.constructor.padLength / 8, this.endian = "big", this._delta8 = this.blockSize / 8, this._delta32 = this.blockSize / 32;
  }
  return oa.BlockHash = t, t.prototype.update = function(o, a) {
    if (o = r.toArray(o, a), this.pending ? this.pending = this.pending.concat(o) : this.pending = o, this.pendingTotal += o.length, this.pending.length >= this._delta8) {
      o = this.pending;
      var p = o.length % this._delta8;
      this.pending = o.slice(o.length - p, o.length), this.pending.length === 0 && (this.pending = null), o = r.join32(o, 0, o.length - p, this.endian);
      for (var c = 0; c < o.length; c += this._delta32)
        this._update(o, c, c + this._delta32);
    }
    return this;
  }, t.prototype.digest = function(o) {
    return this.update(this._pad()), e(this.pending === null), this._digest(o);
  }, t.prototype._pad = function() {
    var o = this.pendingTotal, a = this._delta8, p = a - (o + this.padLength) % a, c = new Array(p + this.padLength);
    c[0] = 128;
    for (var g = 1; g < p; g++)
      c[g] = 0;
    if (o <<= 3, this.endian === "big") {
      for (var h = 8; h < this.padLength; h++)
        c[g++] = 0;
      c[g++] = 0, c[g++] = 0, c[g++] = 0, c[g++] = 0, c[g++] = o >>> 24 & 255, c[g++] = o >>> 16 & 255, c[g++] = o >>> 8 & 255, c[g++] = o & 255;
    } else
      for (c[g++] = o & 255, c[g++] = o >>> 8 & 255, c[g++] = o >>> 16 & 255, c[g++] = o >>> 24 & 255, c[g++] = 0, c[g++] = 0, c[g++] = 0, c[g++] = 0, h = 8; h < this.padLength; h++)
        c[g++] = 0;
    return c;
  }, oa;
}
var Cr = {}, Wt = {}, fo;
function _s() {
  if (fo) return Wt;
  fo = 1;
  var r = Xt(), e = r.rotr32;
  function t(m, S, M, I) {
    if (m === 0)
      return i(S, M, I);
    if (m === 1 || m === 3)
      return a(S, M, I);
    if (m === 2)
      return o(S, M, I);
  }
  Wt.ft_1 = t;
  function i(m, S, M) {
    return m & S ^ ~m & M;
  }
  Wt.ch32 = i;
  function o(m, S, M) {
    return m & S ^ m & M ^ S & M;
  }
  Wt.maj32 = o;
  function a(m, S, M) {
    return m ^ S ^ M;
  }
  Wt.p32 = a;
  function p(m) {
    return e(m, 2) ^ e(m, 13) ^ e(m, 22);
  }
  Wt.s0_256 = p;
  function c(m) {
    return e(m, 6) ^ e(m, 11) ^ e(m, 25);
  }
  Wt.s1_256 = c;
  function g(m) {
    return e(m, 7) ^ e(m, 18) ^ m >>> 3;
  }
  Wt.g0_256 = g;
  function h(m) {
    return e(m, 17) ^ e(m, 19) ^ m >>> 10;
  }
  return Wt.g1_256 = h, Wt;
}
var sa, co;
function lc() {
  if (co) return sa;
  co = 1;
  var r = Xt(), e = ci(), t = _s(), i = r.rotl32, o = r.sum32, a = r.sum32_5, p = t.ft_1, c = e.BlockHash, g = [
    1518500249,
    1859775393,
    2400959708,
    3395469782
  ];
  function h() {
    if (!(this instanceof h))
      return new h();
    c.call(this), this.h = [
      1732584193,
      4023233417,
      2562383102,
      271733878,
      3285377520
    ], this.W = new Array(80);
  }
  return r.inherits(h, c), sa = h, h.blockSize = 512, h.outSize = 160, h.hmacStrength = 80, h.padLength = 64, h.prototype._update = function(S, M) {
    for (var I = this.W, _ = 0; _ < 16; _++)
      I[_] = S[M + _];
    for (; _ < I.length; _++)
      I[_] = i(I[_ - 3] ^ I[_ - 8] ^ I[_ - 14] ^ I[_ - 16], 1);
    var E = this.h[0], O = this.h[1], N = this.h[2], U = this.h[3], j = this.h[4];
    for (_ = 0; _ < I.length; _++) {
      var F = ~~(_ / 20), C = a(i(E, 5), p(F, O, N, U), j, I[_], g[F]);
      j = U, U = N, N = i(O, 30), O = E, E = C;
    }
    this.h[0] = o(this.h[0], E), this.h[1] = o(this.h[1], O), this.h[2] = o(this.h[2], N), this.h[3] = o(this.h[3], U), this.h[4] = o(this.h[4], j);
  }, h.prototype._digest = function(S) {
    return S === "hex" ? r.toHex32(this.h, "big") : r.split32(this.h, "big");
  }, sa;
}
var ua, lo;
function Ms() {
  if (lo) return ua;
  lo = 1;
  var r = Xt(), e = ci(), t = _s(), i = Kr(), o = r.sum32, a = r.sum32_4, p = r.sum32_5, c = t.ch32, g = t.maj32, h = t.s0_256, m = t.s1_256, S = t.g0_256, M = t.g1_256, I = e.BlockHash, _ = [
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
  ];
  function E() {
    if (!(this instanceof E))
      return new E();
    I.call(this), this.h = [
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ], this.k = _, this.W = new Array(64);
  }
  return r.inherits(E, I), ua = E, E.blockSize = 512, E.outSize = 256, E.hmacStrength = 192, E.padLength = 64, E.prototype._update = function(N, U) {
    for (var j = this.W, F = 0; F < 16; F++)
      j[F] = N[U + F];
    for (; F < j.length; F++)
      j[F] = a(M(j[F - 2]), j[F - 7], S(j[F - 15]), j[F - 16]);
    var C = this.h[0], q = this.h[1], V = this.h[2], Z = this.h[3], K = this.h[4], G = this.h[5], z = this.h[6], f = this.h[7];
    for (i(this.k.length === j.length), F = 0; F < j.length; F++) {
      var u = p(f, m(K), c(K, G, z), this.k[F], j[F]), n = o(h(C), g(C, q, V));
      f = z, z = G, G = K, K = o(Z, u), Z = V, V = q, q = C, C = o(u, n);
    }
    this.h[0] = o(this.h[0], C), this.h[1] = o(this.h[1], q), this.h[2] = o(this.h[2], V), this.h[3] = o(this.h[3], Z), this.h[4] = o(this.h[4], K), this.h[5] = o(this.h[5], G), this.h[6] = o(this.h[6], z), this.h[7] = o(this.h[7], f);
  }, E.prototype._digest = function(N) {
    return N === "hex" ? r.toHex32(this.h, "big") : r.split32(this.h, "big");
  }, ua;
}
var fa, ho;
function hc() {
  if (ho) return fa;
  ho = 1;
  var r = Xt(), e = Ms();
  function t() {
    if (!(this instanceof t))
      return new t();
    e.call(this), this.h = [
      3238371032,
      914150663,
      812702999,
      4144912697,
      4290775857,
      1750603025,
      1694076839,
      3204075428
    ];
  }
  return r.inherits(t, e), fa = t, t.blockSize = 512, t.outSize = 224, t.hmacStrength = 192, t.padLength = 64, t.prototype._digest = function(o) {
    return o === "hex" ? r.toHex32(this.h.slice(0, 7), "big") : r.split32(this.h.slice(0, 7), "big");
  }, fa;
}
var ca, po;
function Bs() {
  if (po) return ca;
  po = 1;
  var r = Xt(), e = ci(), t = Kr(), i = r.rotr64_hi, o = r.rotr64_lo, a = r.shr64_hi, p = r.shr64_lo, c = r.sum64, g = r.sum64_hi, h = r.sum64_lo, m = r.sum64_4_hi, S = r.sum64_4_lo, M = r.sum64_5_hi, I = r.sum64_5_lo, _ = e.BlockHash, E = [
    1116352408,
    3609767458,
    1899447441,
    602891725,
    3049323471,
    3964484399,
    3921009573,
    2173295548,
    961987163,
    4081628472,
    1508970993,
    3053834265,
    2453635748,
    2937671579,
    2870763221,
    3664609560,
    3624381080,
    2734883394,
    310598401,
    1164996542,
    607225278,
    1323610764,
    1426881987,
    3590304994,
    1925078388,
    4068182383,
    2162078206,
    991336113,
    2614888103,
    633803317,
    3248222580,
    3479774868,
    3835390401,
    2666613458,
    4022224774,
    944711139,
    264347078,
    2341262773,
    604807628,
    2007800933,
    770255983,
    1495990901,
    1249150122,
    1856431235,
    1555081692,
    3175218132,
    1996064986,
    2198950837,
    2554220882,
    3999719339,
    2821834349,
    766784016,
    2952996808,
    2566594879,
    3210313671,
    3203337956,
    3336571891,
    1034457026,
    3584528711,
    2466948901,
    113926993,
    3758326383,
    338241895,
    168717936,
    666307205,
    1188179964,
    773529912,
    1546045734,
    1294757372,
    1522805485,
    1396182291,
    2643833823,
    1695183700,
    2343527390,
    1986661051,
    1014477480,
    2177026350,
    1206759142,
    2456956037,
    344077627,
    2730485921,
    1290863460,
    2820302411,
    3158454273,
    3259730800,
    3505952657,
    3345764771,
    106217008,
    3516065817,
    3606008344,
    3600352804,
    1432725776,
    4094571909,
    1467031594,
    275423344,
    851169720,
    430227734,
    3100823752,
    506948616,
    1363258195,
    659060556,
    3750685593,
    883997877,
    3785050280,
    958139571,
    3318307427,
    1322822218,
    3812723403,
    1537002063,
    2003034995,
    1747873779,
    3602036899,
    1955562222,
    1575990012,
    2024104815,
    1125592928,
    2227730452,
    2716904306,
    2361852424,
    442776044,
    2428436474,
    593698344,
    2756734187,
    3733110249,
    3204031479,
    2999351573,
    3329325298,
    3815920427,
    3391569614,
    3928383900,
    3515267271,
    566280711,
    3940187606,
    3454069534,
    4118630271,
    4000239992,
    116418474,
    1914138554,
    174292421,
    2731055270,
    289380356,
    3203993006,
    460393269,
    320620315,
    685471733,
    587496836,
    852142971,
    1086792851,
    1017036298,
    365543100,
    1126000580,
    2618297676,
    1288033470,
    3409855158,
    1501505948,
    4234509866,
    1607167915,
    987167468,
    1816402316,
    1246189591
  ];
  function O() {
    if (!(this instanceof O))
      return new O();
    _.call(this), this.h = [
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
    ], this.k = E, this.W = new Array(160);
  }
  r.inherits(O, _), ca = O, O.blockSize = 1024, O.outSize = 512, O.hmacStrength = 192, O.padLength = 128, O.prototype._prepareBlock = function(n, s) {
    for (var d = this.W, w = 0; w < 32; w++)
      d[w] = n[s + w];
    for (; w < d.length; w += 2) {
      var A = z(d[w - 4], d[w - 3]), k = f(d[w - 4], d[w - 3]), l = d[w - 14], y = d[w - 13], v = K(d[w - 30], d[w - 29]), P = G(d[w - 30], d[w - 29]), J = d[w - 32], Y = d[w - 31];
      d[w] = m(
        A,
        k,
        l,
        y,
        v,
        P,
        J,
        Y
      ), d[w + 1] = S(
        A,
        k,
        l,
        y,
        v,
        P,
        J,
        Y
      );
    }
  }, O.prototype._update = function(n, s) {
    this._prepareBlock(n, s);
    var d = this.W, w = this.h[0], A = this.h[1], k = this.h[2], l = this.h[3], y = this.h[4], v = this.h[5], P = this.h[6], J = this.h[7], Y = this.h[8], Q = this.h[9], se = this.h[10], pe = this.h[11], ne = this.h[12], Ne = this.h[13], qe = this.h[14], he = this.h[15];
    t(this.k.length === d.length);
    for (var Ee = 0; Ee < d.length; Ee += 2) {
      var Ce = qe, fe = he, Re = V(Y, Q), Fe = Z(Y, Q), me = N(Y, Q, se, pe, ne), He = U(Y, Q, se, pe, ne, Ne), De = this.k[Ee], ce = this.k[Ee + 1], Pe = d[Ee], je = d[Ee + 1], de = M(
        Ce,
        fe,
        Re,
        Fe,
        me,
        He,
        De,
        ce,
        Pe,
        je
      ), Te = I(
        Ce,
        fe,
        Re,
        Fe,
        me,
        He,
        De,
        ce,
        Pe,
        je
      );
      Ce = C(w, A), fe = q(w, A), Re = j(w, A, k, l, y), Fe = F(w, A, k, l, y, v);
      var Ve = g(Ce, fe, Re, Fe), B = h(Ce, fe, Re, Fe);
      qe = ne, he = Ne, ne = se, Ne = pe, se = Y, pe = Q, Y = g(P, J, de, Te), Q = h(J, J, de, Te), P = y, J = v, y = k, v = l, k = w, l = A, w = g(de, Te, Ve, B), A = h(de, Te, Ve, B);
    }
    c(this.h, 0, w, A), c(this.h, 2, k, l), c(this.h, 4, y, v), c(this.h, 6, P, J), c(this.h, 8, Y, Q), c(this.h, 10, se, pe), c(this.h, 12, ne, Ne), c(this.h, 14, qe, he);
  }, O.prototype._digest = function(n) {
    return n === "hex" ? r.toHex32(this.h, "big") : r.split32(this.h, "big");
  };
  function N(u, n, s, d, w) {
    var A = u & s ^ ~u & w;
    return A < 0 && (A += 4294967296), A;
  }
  function U(u, n, s, d, w, A) {
    var k = n & d ^ ~n & A;
    return k < 0 && (k += 4294967296), k;
  }
  function j(u, n, s, d, w) {
    var A = u & s ^ u & w ^ s & w;
    return A < 0 && (A += 4294967296), A;
  }
  function F(u, n, s, d, w, A) {
    var k = n & d ^ n & A ^ d & A;
    return k < 0 && (k += 4294967296), k;
  }
  function C(u, n) {
    var s = i(u, n, 28), d = i(n, u, 2), w = i(n, u, 7), A = s ^ d ^ w;
    return A < 0 && (A += 4294967296), A;
  }
  function q(u, n) {
    var s = o(u, n, 28), d = o(n, u, 2), w = o(n, u, 7), A = s ^ d ^ w;
    return A < 0 && (A += 4294967296), A;
  }
  function V(u, n) {
    var s = i(u, n, 14), d = i(u, n, 18), w = i(n, u, 9), A = s ^ d ^ w;
    return A < 0 && (A += 4294967296), A;
  }
  function Z(u, n) {
    var s = o(u, n, 14), d = o(u, n, 18), w = o(n, u, 9), A = s ^ d ^ w;
    return A < 0 && (A += 4294967296), A;
  }
  function K(u, n) {
    var s = i(u, n, 1), d = i(u, n, 8), w = a(u, n, 7), A = s ^ d ^ w;
    return A < 0 && (A += 4294967296), A;
  }
  function G(u, n) {
    var s = o(u, n, 1), d = o(u, n, 8), w = p(u, n, 7), A = s ^ d ^ w;
    return A < 0 && (A += 4294967296), A;
  }
  function z(u, n) {
    var s = i(u, n, 19), d = i(n, u, 29), w = a(u, n, 6), A = s ^ d ^ w;
    return A < 0 && (A += 4294967296), A;
  }
  function f(u, n) {
    var s = o(u, n, 19), d = o(n, u, 29), w = p(u, n, 6), A = s ^ d ^ w;
    return A < 0 && (A += 4294967296), A;
  }
  return ca;
}
var la, mo;
function dc() {
  if (mo) return la;
  mo = 1;
  var r = Xt(), e = Bs();
  function t() {
    if (!(this instanceof t))
      return new t();
    e.call(this), this.h = [
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
    ];
  }
  return r.inherits(t, e), la = t, t.blockSize = 1024, t.outSize = 384, t.hmacStrength = 192, t.padLength = 128, t.prototype._digest = function(o) {
    return o === "hex" ? r.toHex32(this.h.slice(0, 12), "big") : r.split32(this.h.slice(0, 12), "big");
  }, la;
}
var bo;
function pc() {
  return bo || (bo = 1, Cr.sha1 = lc(), Cr.sha224 = hc(), Cr.sha256 = Ms(), Cr.sha384 = dc(), Cr.sha512 = Bs()), Cr;
}
var ha = {}, vo;
function mc() {
  if (vo) return ha;
  vo = 1;
  var r = Xt(), e = ci(), t = r.rotl32, i = r.sum32, o = r.sum32_3, a = r.sum32_4, p = e.BlockHash;
  function c() {
    if (!(this instanceof c))
      return new c();
    p.call(this), this.h = [1732584193, 4023233417, 2562383102, 271733878, 3285377520], this.endian = "little";
  }
  r.inherits(c, p), ha.ripemd160 = c, c.blockSize = 512, c.outSize = 160, c.hmacStrength = 192, c.padLength = 64, c.prototype._update = function(O, N) {
    for (var U = this.h[0], j = this.h[1], F = this.h[2], C = this.h[3], q = this.h[4], V = U, Z = j, K = F, G = C, z = q, f = 0; f < 80; f++) {
      var u = i(
        t(
          a(U, g(f, j, F, C), O[S[f] + N], h(f)),
          I[f]
        ),
        q
      );
      U = q, q = C, C = t(F, 10), F = j, j = u, u = i(
        t(
          a(V, g(79 - f, Z, K, G), O[M[f] + N], m(f)),
          _[f]
        ),
        z
      ), V = z, z = G, G = t(K, 10), K = Z, Z = u;
    }
    u = o(this.h[1], F, G), this.h[1] = o(this.h[2], C, z), this.h[2] = o(this.h[3], q, V), this.h[3] = o(this.h[4], U, Z), this.h[4] = o(this.h[0], j, K), this.h[0] = u;
  }, c.prototype._digest = function(O) {
    return O === "hex" ? r.toHex32(this.h, "little") : r.split32(this.h, "little");
  };
  function g(E, O, N, U) {
    return E <= 15 ? O ^ N ^ U : E <= 31 ? O & N | ~O & U : E <= 47 ? (O | ~N) ^ U : E <= 63 ? O & U | N & ~U : O ^ (N | ~U);
  }
  function h(E) {
    return E <= 15 ? 0 : E <= 31 ? 1518500249 : E <= 47 ? 1859775393 : E <= 63 ? 2400959708 : 2840853838;
  }
  function m(E) {
    return E <= 15 ? 1352829926 : E <= 31 ? 1548603684 : E <= 47 ? 1836072691 : E <= 63 ? 2053994217 : 0;
  }
  var S = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    7,
    4,
    13,
    1,
    10,
    6,
    15,
    3,
    12,
    0,
    9,
    5,
    2,
    14,
    11,
    8,
    3,
    10,
    14,
    4,
    9,
    15,
    8,
    1,
    2,
    7,
    0,
    6,
    13,
    11,
    5,
    12,
    1,
    9,
    11,
    10,
    0,
    8,
    12,
    4,
    13,
    3,
    7,
    15,
    14,
    5,
    6,
    2,
    4,
    0,
    5,
    9,
    7,
    12,
    2,
    10,
    14,
    1,
    3,
    8,
    11,
    6,
    15,
    13
  ], M = [
    5,
    14,
    7,
    0,
    9,
    2,
    11,
    4,
    13,
    6,
    15,
    8,
    1,
    10,
    3,
    12,
    6,
    11,
    3,
    7,
    0,
    13,
    5,
    10,
    14,
    15,
    8,
    12,
    4,
    9,
    1,
    2,
    15,
    5,
    1,
    3,
    7,
    14,
    6,
    9,
    11,
    8,
    12,
    2,
    10,
    0,
    4,
    13,
    8,
    6,
    4,
    1,
    3,
    11,
    15,
    0,
    5,
    12,
    2,
    13,
    9,
    7,
    10,
    14,
    12,
    15,
    10,
    4,
    1,
    5,
    8,
    7,
    6,
    2,
    13,
    14,
    0,
    3,
    9,
    11
  ], I = [
    11,
    14,
    15,
    12,
    5,
    8,
    7,
    9,
    11,
    13,
    14,
    15,
    6,
    7,
    9,
    8,
    7,
    6,
    8,
    13,
    11,
    9,
    7,
    15,
    7,
    12,
    15,
    9,
    11,
    7,
    13,
    12,
    11,
    13,
    6,
    7,
    14,
    9,
    13,
    15,
    14,
    8,
    13,
    6,
    5,
    12,
    7,
    5,
    11,
    12,
    14,
    15,
    14,
    15,
    9,
    8,
    9,
    14,
    5,
    6,
    8,
    6,
    5,
    12,
    9,
    15,
    5,
    11,
    6,
    8,
    13,
    12,
    5,
    12,
    13,
    14,
    11,
    8,
    5,
    6
  ], _ = [
    8,
    9,
    9,
    11,
    13,
    15,
    15,
    5,
    7,
    7,
    8,
    11,
    14,
    14,
    12,
    6,
    9,
    13,
    15,
    7,
    12,
    8,
    9,
    11,
    7,
    7,
    12,
    7,
    6,
    15,
    13,
    11,
    9,
    7,
    15,
    11,
    8,
    6,
    6,
    14,
    12,
    13,
    5,
    14,
    13,
    13,
    7,
    5,
    15,
    5,
    8,
    11,
    14,
    14,
    6,
    14,
    6,
    9,
    12,
    9,
    12,
    5,
    15,
    8,
    8,
    5,
    12,
    9,
    12,
    5,
    14,
    6,
    8,
    13,
    6,
    5,
    15,
    13,
    11,
    11
  ];
  return ha;
}
var da, go;
function bc() {
  if (go) return da;
  go = 1;
  var r = Xt(), e = Kr();
  function t(i, o, a) {
    if (!(this instanceof t))
      return new t(i, o, a);
    this.Hash = i, this.blockSize = i.blockSize / 8, this.outSize = i.outSize / 8, this.inner = null, this.outer = null, this._init(r.toArray(o, a));
  }
  return da = t, t.prototype._init = function(o) {
    o.length > this.blockSize && (o = new this.Hash().update(o).digest()), e(o.length <= this.blockSize);
    for (var a = o.length; a < this.blockSize; a++)
      o.push(0);
    for (a = 0; a < o.length; a++)
      o[a] ^= 54;
    for (this.inner = new this.Hash().update(o), a = 0; a < o.length; a++)
      o[a] ^= 106;
    this.outer = new this.Hash().update(o);
  }, t.prototype.update = function(o, a) {
    return this.inner.update(o, a), this;
  }, t.prototype.digest = function(o) {
    return this.outer.update(this.inner.digest()), this.outer.digest(o);
  }, da;
}
var yo;
function on() {
  return yo || (yo = 1, (function(r) {
    var e = r;
    e.utils = Xt(), e.common = ci(), e.sha = pc(), e.ripemd = mc(), e.hmac = bc(), e.sha1 = e.sha.sha1, e.sha256 = e.sha.sha256, e.sha224 = e.sha.sha224, e.sha384 = e.sha.sha384, e.sha512 = e.sha.sha512, e.ripemd160 = e.ripemd.ripemd160;
  })(na)), na;
}
var pa, wo;
function vc() {
  return wo || (wo = 1, pa = {
    doubles: {
      step: 4,
      points: [
        [
          "e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
          "f7e3507399e595929db99f34f57937101296891e44d23f0be1f32cce69616821"
        ],
        [
          "8282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508",
          "11f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf"
        ],
        [
          "175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739",
          "d3506e0d9e3c79eba4ef97a51ff71f5eacb5955add24345c6efa6ffee9fed695"
        ],
        [
          "363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640",
          "4e273adfc732221953b445397f3363145b9a89008199ecb62003c7f3bee9de9"
        ],
        [
          "8b4b5f165df3c2be8c6244b5b745638843e4a781a15bcd1b69f79a55dffdf80c",
          "4aad0a6f68d308b4b3fbd7813ab0da04f9e336546162ee56b3eff0c65fd4fd36"
        ],
        [
          "723cbaa6e5db996d6bf771c00bd548c7b700dbffa6c0e77bcb6115925232fcda",
          "96e867b5595cc498a921137488824d6e2660a0653779494801dc069d9eb39f5f"
        ],
        [
          "eebfa4d493bebf98ba5feec812c2d3b50947961237a919839a533eca0e7dd7fa",
          "5d9a8ca3970ef0f269ee7edaf178089d9ae4cdc3a711f712ddfd4fdae1de8999"
        ],
        [
          "100f44da696e71672791d0a09b7bde459f1215a29b3c03bfefd7835b39a48db0",
          "cdd9e13192a00b772ec8f3300c090666b7ff4a18ff5195ac0fbd5cd62bc65a09"
        ],
        [
          "e1031be262c7ed1b1dc9227a4a04c017a77f8d4464f3b3852c8acde6e534fd2d",
          "9d7061928940405e6bb6a4176597535af292dd419e1ced79a44f18f29456a00d"
        ],
        [
          "feea6cae46d55b530ac2839f143bd7ec5cf8b266a41d6af52d5e688d9094696d",
          "e57c6b6c97dce1bab06e4e12bf3ecd5c981c8957cc41442d3155debf18090088"
        ],
        [
          "da67a91d91049cdcb367be4be6ffca3cfeed657d808583de33fa978bc1ec6cb1",
          "9bacaa35481642bc41f463f7ec9780e5dec7adc508f740a17e9ea8e27a68be1d"
        ],
        [
          "53904faa0b334cdda6e000935ef22151ec08d0f7bb11069f57545ccc1a37b7c0",
          "5bc087d0bc80106d88c9eccac20d3c1c13999981e14434699dcb096b022771c8"
        ],
        [
          "8e7bcd0bd35983a7719cca7764ca906779b53a043a9b8bcaeff959f43ad86047",
          "10b7770b2a3da4b3940310420ca9514579e88e2e47fd68b3ea10047e8460372a"
        ],
        [
          "385eed34c1cdff21e6d0818689b81bde71a7f4f18397e6690a841e1599c43862",
          "283bebc3e8ea23f56701de19e9ebf4576b304eec2086dc8cc0458fe5542e5453"
        ],
        [
          "6f9d9b803ecf191637c73a4413dfa180fddf84a5947fbc9c606ed86c3fac3a7",
          "7c80c68e603059ba69b8e2a30e45c4d47ea4dd2f5c281002d86890603a842160"
        ],
        [
          "3322d401243c4e2582a2147c104d6ecbf774d163db0f5e5313b7e0e742d0e6bd",
          "56e70797e9664ef5bfb019bc4ddaf9b72805f63ea2873af624f3a2e96c28b2a0"
        ],
        [
          "85672c7d2de0b7da2bd1770d89665868741b3f9af7643397721d74d28134ab83",
          "7c481b9b5b43b2eb6374049bfa62c2e5e77f17fcc5298f44c8e3094f790313a6"
        ],
        [
          "948bf809b1988a46b06c9f1919413b10f9226c60f668832ffd959af60c82a0a",
          "53a562856dcb6646dc6b74c5d1c3418c6d4dff08c97cd2bed4cb7f88d8c8e589"
        ],
        [
          "6260ce7f461801c34f067ce0f02873a8f1b0e44dfc69752accecd819f38fd8e8",
          "bc2da82b6fa5b571a7f09049776a1ef7ecd292238051c198c1a84e95b2b4ae17"
        ],
        [
          "e5037de0afc1d8d43d8348414bbf4103043ec8f575bfdc432953cc8d2037fa2d",
          "4571534baa94d3b5f9f98d09fb990bddbd5f5b03ec481f10e0e5dc841d755bda"
        ],
        [
          "e06372b0f4a207adf5ea905e8f1771b4e7e8dbd1c6a6c5b725866a0ae4fce725",
          "7a908974bce18cfe12a27bb2ad5a488cd7484a7787104870b27034f94eee31dd"
        ],
        [
          "213c7a715cd5d45358d0bbf9dc0ce02204b10bdde2a3f58540ad6908d0559754",
          "4b6dad0b5ae462507013ad06245ba190bb4850f5f36a7eeddff2c27534b458f2"
        ],
        [
          "4e7c272a7af4b34e8dbb9352a5419a87e2838c70adc62cddf0cc3a3b08fbd53c",
          "17749c766c9d0b18e16fd09f6def681b530b9614bff7dd33e0b3941817dcaae6"
        ],
        [
          "fea74e3dbe778b1b10f238ad61686aa5c76e3db2be43057632427e2840fb27b6",
          "6e0568db9b0b13297cf674deccb6af93126b596b973f7b77701d3db7f23cb96f"
        ],
        [
          "76e64113f677cf0e10a2570d599968d31544e179b760432952c02a4417bdde39",
          "c90ddf8dee4e95cf577066d70681f0d35e2a33d2b56d2032b4b1752d1901ac01"
        ],
        [
          "c738c56b03b2abe1e8281baa743f8f9a8f7cc643df26cbee3ab150242bcbb891",
          "893fb578951ad2537f718f2eacbfbbbb82314eef7880cfe917e735d9699a84c3"
        ],
        [
          "d895626548b65b81e264c7637c972877d1d72e5f3a925014372e9f6588f6c14b",
          "febfaa38f2bc7eae728ec60818c340eb03428d632bb067e179363ed75d7d991f"
        ],
        [
          "b8da94032a957518eb0f6433571e8761ceffc73693e84edd49150a564f676e03",
          "2804dfa44805a1e4d7c99cc9762808b092cc584d95ff3b511488e4e74efdf6e7"
        ],
        [
          "e80fea14441fb33a7d8adab9475d7fab2019effb5156a792f1a11778e3c0df5d",
          "eed1de7f638e00771e89768ca3ca94472d155e80af322ea9fcb4291b6ac9ec78"
        ],
        [
          "a301697bdfcd704313ba48e51d567543f2a182031efd6915ddc07bbcc4e16070",
          "7370f91cfb67e4f5081809fa25d40f9b1735dbf7c0a11a130c0d1a041e177ea1"
        ],
        [
          "90ad85b389d6b936463f9d0512678de208cc330b11307fffab7ac63e3fb04ed4",
          "e507a3620a38261affdcbd9427222b839aefabe1582894d991d4d48cb6ef150"
        ],
        [
          "8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da",
          "662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82"
        ],
        [
          "e4f3fb0176af85d65ff99ff9198c36091f48e86503681e3e6686fd5053231e11",
          "1e63633ad0ef4f1c1661a6d0ea02b7286cc7e74ec951d1c9822c38576feb73bc"
        ],
        [
          "8c00fa9b18ebf331eb961537a45a4266c7034f2f0d4e1d0716fb6eae20eae29e",
          "efa47267fea521a1a9dc343a3736c974c2fadafa81e36c54e7d2a4c66702414b"
        ],
        [
          "e7a26ce69dd4829f3e10cec0a9e98ed3143d084f308b92c0997fddfc60cb3e41",
          "2a758e300fa7984b471b006a1aafbb18d0a6b2c0420e83e20e8a9421cf2cfd51"
        ],
        [
          "b6459e0ee3662ec8d23540c223bcbdc571cbcb967d79424f3cf29eb3de6b80ef",
          "67c876d06f3e06de1dadf16e5661db3c4b3ae6d48e35b2ff30bf0b61a71ba45"
        ],
        [
          "d68a80c8280bb840793234aa118f06231d6f1fc67e73c5a5deda0f5b496943e8",
          "db8ba9fff4b586d00c4b1f9177b0e28b5b0e7b8f7845295a294c84266b133120"
        ],
        [
          "324aed7df65c804252dc0270907a30b09612aeb973449cea4095980fc28d3d5d",
          "648a365774b61f2ff130c0c35aec1f4f19213b0c7e332843967224af96ab7c84"
        ],
        [
          "4df9c14919cde61f6d51dfdbe5fee5dceec4143ba8d1ca888e8bd373fd054c96",
          "35ec51092d8728050974c23a1d85d4b5d506cdc288490192ebac06cad10d5d"
        ],
        [
          "9c3919a84a474870faed8a9c1cc66021523489054d7f0308cbfc99c8ac1f98cd",
          "ddb84f0f4a4ddd57584f044bf260e641905326f76c64c8e6be7e5e03d4fc599d"
        ],
        [
          "6057170b1dd12fdf8de05f281d8e06bb91e1493a8b91d4cc5a21382120a959e5",
          "9a1af0b26a6a4807add9a2daf71df262465152bc3ee24c65e899be932385a2a8"
        ],
        [
          "a576df8e23a08411421439a4518da31880cef0fba7d4df12b1a6973eecb94266",
          "40a6bf20e76640b2c92b97afe58cd82c432e10a7f514d9f3ee8be11ae1b28ec8"
        ],
        [
          "7778a78c28dec3e30a05fe9629de8c38bb30d1f5cf9a3a208f763889be58ad71",
          "34626d9ab5a5b22ff7098e12f2ff580087b38411ff24ac563b513fc1fd9f43ac"
        ],
        [
          "928955ee637a84463729fd30e7afd2ed5f96274e5ad7e5cb09eda9c06d903ac",
          "c25621003d3f42a827b78a13093a95eeac3d26efa8a8d83fc5180e935bcd091f"
        ],
        [
          "85d0fef3ec6db109399064f3a0e3b2855645b4a907ad354527aae75163d82751",
          "1f03648413a38c0be29d496e582cf5663e8751e96877331582c237a24eb1f962"
        ],
        [
          "ff2b0dce97eece97c1c9b6041798b85dfdfb6d8882da20308f5404824526087e",
          "493d13fef524ba188af4c4dc54d07936c7b7ed6fb90e2ceb2c951e01f0c29907"
        ],
        [
          "827fbbe4b1e880ea9ed2b2e6301b212b57f1ee148cd6dd28780e5e2cf856e241",
          "c60f9c923c727b0b71bef2c67d1d12687ff7a63186903166d605b68baec293ec"
        ],
        [
          "eaa649f21f51bdbae7be4ae34ce6e5217a58fdce7f47f9aa7f3b58fa2120e2b3",
          "be3279ed5bbbb03ac69a80f89879aa5a01a6b965f13f7e59d47a5305ba5ad93d"
        ],
        [
          "e4a42d43c5cf169d9391df6decf42ee541b6d8f0c9a137401e23632dda34d24f",
          "4d9f92e716d1c73526fc99ccfb8ad34ce886eedfa8d8e4f13a7f7131deba9414"
        ],
        [
          "1ec80fef360cbdd954160fadab352b6b92b53576a88fea4947173b9d4300bf19",
          "aeefe93756b5340d2f3a4958a7abbf5e0146e77f6295a07b671cdc1cc107cefd"
        ],
        [
          "146a778c04670c2f91b00af4680dfa8bce3490717d58ba889ddb5928366642be",
          "b318e0ec3354028add669827f9d4b2870aaa971d2f7e5ed1d0b297483d83efd0"
        ],
        [
          "fa50c0f61d22e5f07e3acebb1aa07b128d0012209a28b9776d76a8793180eef9",
          "6b84c6922397eba9b72cd2872281a68a5e683293a57a213b38cd8d7d3f4f2811"
        ],
        [
          "da1d61d0ca721a11b1a5bf6b7d88e8421a288ab5d5bba5220e53d32b5f067ec2",
          "8157f55a7c99306c79c0766161c91e2966a73899d279b48a655fba0f1ad836f1"
        ],
        [
          "a8e282ff0c9706907215ff98e8fd416615311de0446f1e062a73b0610d064e13",
          "7f97355b8db81c09abfb7f3c5b2515888b679a3e50dd6bd6cef7c73111f4cc0c"
        ],
        [
          "174a53b9c9a285872d39e56e6913cab15d59b1fa512508c022f382de8319497c",
          "ccc9dc37abfc9c1657b4155f2c47f9e6646b3a1d8cb9854383da13ac079afa73"
        ],
        [
          "959396981943785c3d3e57edf5018cdbe039e730e4918b3d884fdff09475b7ba",
          "2e7e552888c331dd8ba0386a4b9cd6849c653f64c8709385e9b8abf87524f2fd"
        ],
        [
          "d2a63a50ae401e56d645a1153b109a8fcca0a43d561fba2dbb51340c9d82b151",
          "e82d86fb6443fcb7565aee58b2948220a70f750af484ca52d4142174dcf89405"
        ],
        [
          "64587e2335471eb890ee7896d7cfdc866bacbdbd3839317b3436f9b45617e073",
          "d99fcdd5bf6902e2ae96dd6447c299a185b90a39133aeab358299e5e9faf6589"
        ],
        [
          "8481bde0e4e4d885b3a546d3e549de042f0aa6cea250e7fd358d6c86dd45e458",
          "38ee7b8cba5404dd84a25bf39cecb2ca900a79c42b262e556d64b1b59779057e"
        ],
        [
          "13464a57a78102aa62b6979ae817f4637ffcfed3c4b1ce30bcd6303f6caf666b",
          "69be159004614580ef7e433453ccb0ca48f300a81d0942e13f495a907f6ecc27"
        ],
        [
          "bc4a9df5b713fe2e9aef430bcc1dc97a0cd9ccede2f28588cada3a0d2d83f366",
          "d3a81ca6e785c06383937adf4b798caa6e8a9fbfa547b16d758d666581f33c1"
        ],
        [
          "8c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa",
          "40a30463a3305193378fedf31f7cc0eb7ae784f0451cb9459e71dc73cbef9482"
        ],
        [
          "8ea9666139527a8c1dd94ce4f071fd23c8b350c5a4bb33748c4ba111faccae0",
          "620efabbc8ee2782e24e7c0cfb95c5d735b783be9cf0f8e955af34a30e62b945"
        ],
        [
          "dd3625faef5ba06074669716bbd3788d89bdde815959968092f76cc4eb9a9787",
          "7a188fa3520e30d461da2501045731ca941461982883395937f68d00c644a573"
        ],
        [
          "f710d79d9eb962297e4f6232b40e8f7feb2bc63814614d692c12de752408221e",
          "ea98e67232d3b3295d3b535532115ccac8612c721851617526ae47a9c77bfc82"
        ]
      ]
    },
    naf: {
      wnd: 7,
      points: [
        [
          "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
          "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"
        ],
        [
          "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
          "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6"
        ],
        [
          "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
          "6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da"
        ],
        [
          "acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
          "cc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37"
        ],
        [
          "774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb",
          "d984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b"
        ],
        [
          "f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",
          "ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81"
        ],
        [
          "d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e",
          "581e2872a86c72a683842ec228cc6defea40af2bd896d3a5c504dc9ff6a26b58"
        ],
        [
          "defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
          "4211ab0694635168e997b0ead2a93daeced1f4a04a95c0f6cfb199f69e56eb77"
        ],
        [
          "2b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c",
          "85e89bc037945d93b343083b5a1c86131a01f60c50269763b570c854e5c09b7a"
        ],
        [
          "352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5",
          "321eb4075348f534d59c18259dda3e1f4a1b3b2e71b1039c67bd3d8bcf81998c"
        ],
        [
          "2fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f",
          "2de1068295dd865b64569335bd5dd80181d70ecfc882648423ba76b532b7d67"
        ],
        [
          "9248279b09b4d68dab21a9b066edda83263c3d84e09572e269ca0cd7f5453714",
          "73016f7bf234aade5d1aa71bdea2b1ff3fc0de2a887912ffe54a32ce97cb3402"
        ],
        [
          "daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729",
          "a69dce4a7d6c98e8d4a1aca87ef8d7003f83c230f3afa726ab40e52290be1c55"
        ],
        [
          "c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db",
          "2119a460ce326cdc76c45926c982fdac0e106e861edf61c5a039063f0e0e6482"
        ],
        [
          "6a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4",
          "e022cf42c2bd4a708b3f5126f16a24ad8b33ba48d0423b6efd5e6348100d8a82"
        ],
        [
          "1697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5",
          "b9c398f186806f5d27561506e4557433a2cf15009e498ae7adee9d63d01b2396"
        ],
        [
          "605bdb019981718b986d0f07e834cb0d9deb8360ffb7f61df982345ef27a7479",
          "2972d2de4f8d20681a78d93ec96fe23c26bfae84fb14db43b01e1e9056b8c49"
        ],
        [
          "62d14dab4150bf497402fdc45a215e10dcb01c354959b10cfe31c7e9d87ff33d",
          "80fc06bd8cc5b01098088a1950eed0db01aa132967ab472235f5642483b25eaf"
        ],
        [
          "80c60ad0040f27dade5b4b06c408e56b2c50e9f56b9b8b425e555c2f86308b6f",
          "1c38303f1cc5c30f26e66bad7fe72f70a65eed4cbe7024eb1aa01f56430bd57a"
        ],
        [
          "7a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb",
          "d0e3fa9eca8726909559e0d79269046bdc59ea10c70ce2b02d499ec224dc7f7"
        ],
        [
          "d528ecd9b696b54c907a9ed045447a79bb408ec39b68df504bb51f459bc3ffc9",
          "eecf41253136e5f99966f21881fd656ebc4345405c520dbc063465b521409933"
        ],
        [
          "49370a4b5f43412ea25f514e8ecdad05266115e4a7ecb1387231808f8b45963",
          "758f3f41afd6ed428b3081b0512fd62a54c3f3afbb5b6764b653052a12949c9a"
        ],
        [
          "77f230936ee88cbbd73df930d64702ef881d811e0e1498e2f1c13eb1fc345d74",
          "958ef42a7886b6400a08266e9ba1b37896c95330d97077cbbe8eb3c7671c60d6"
        ],
        [
          "f2dac991cc4ce4b9ea44887e5c7c0bce58c80074ab9d4dbaeb28531b7739f530",
          "e0dedc9b3b2f8dad4da1f32dec2531df9eb5fbeb0598e4fd1a117dba703a3c37"
        ],
        [
          "463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b",
          "5ed430d78c296c3543114306dd8622d7c622e27c970a1de31cb377b01af7307e"
        ],
        [
          "f16f804244e46e2a09232d4aff3b59976b98fac14328a2d1a32496b49998f247",
          "cedabd9b82203f7e13d206fcdf4e33d92a6c53c26e5cce26d6579962c4e31df6"
        ],
        [
          "caf754272dc84563b0352b7a14311af55d245315ace27c65369e15f7151d41d1",
          "cb474660ef35f5f2a41b643fa5e460575f4fa9b7962232a5c32f908318a04476"
        ],
        [
          "2600ca4b282cb986f85d0f1709979d8b44a09c07cb86d7c124497bc86f082120",
          "4119b88753c15bd6a693b03fcddbb45d5ac6be74ab5f0ef44b0be9475a7e4b40"
        ],
        [
          "7635ca72d7e8432c338ec53cd12220bc01c48685e24f7dc8c602a7746998e435",
          "91b649609489d613d1d5e590f78e6d74ecfc061d57048bad9e76f302c5b9c61"
        ],
        [
          "754e3239f325570cdbbf4a87deee8a66b7f2b33479d468fbc1a50743bf56cc18",
          "673fb86e5bda30fb3cd0ed304ea49a023ee33d0197a695d0c5d98093c536683"
        ],
        [
          "e3e6bd1071a1e96aff57859c82d570f0330800661d1c952f9fe2694691d9b9e8",
          "59c9e0bba394e76f40c0aa58379a3cb6a5a2283993e90c4167002af4920e37f5"
        ],
        [
          "186b483d056a033826ae73d88f732985c4ccb1f32ba35f4b4cc47fdcf04aa6eb",
          "3b952d32c67cf77e2e17446e204180ab21fb8090895138b4a4a797f86e80888b"
        ],
        [
          "df9d70a6b9876ce544c98561f4be4f725442e6d2b737d9c91a8321724ce0963f",
          "55eb2dafd84d6ccd5f862b785dc39d4ab157222720ef9da217b8c45cf2ba2417"
        ],
        [
          "5edd5cc23c51e87a497ca815d5dce0f8ab52554f849ed8995de64c5f34ce7143",
          "efae9c8dbc14130661e8cec030c89ad0c13c66c0d17a2905cdc706ab7399a868"
        ],
        [
          "290798c2b6476830da12fe02287e9e777aa3fba1c355b17a722d362f84614fba",
          "e38da76dcd440621988d00bcf79af25d5b29c094db2a23146d003afd41943e7a"
        ],
        [
          "af3c423a95d9f5b3054754efa150ac39cd29552fe360257362dfdecef4053b45",
          "f98a3fd831eb2b749a93b0e6f35cfb40c8cd5aa667a15581bc2feded498fd9c6"
        ],
        [
          "766dbb24d134e745cccaa28c99bf274906bb66b26dcf98df8d2fed50d884249a",
          "744b1152eacbe5e38dcc887980da38b897584a65fa06cedd2c924f97cbac5996"
        ],
        [
          "59dbf46f8c94759ba21277c33784f41645f7b44f6c596a58ce92e666191abe3e",
          "c534ad44175fbc300f4ea6ce648309a042ce739a7919798cd85e216c4a307f6e"
        ],
        [
          "f13ada95103c4537305e691e74e9a4a8dd647e711a95e73cb62dc6018cfd87b8",
          "e13817b44ee14de663bf4bc808341f326949e21a6a75c2570778419bdaf5733d"
        ],
        [
          "7754b4fa0e8aced06d4167a2c59cca4cda1869c06ebadfb6488550015a88522c",
          "30e93e864e669d82224b967c3020b8fa8d1e4e350b6cbcc537a48b57841163a2"
        ],
        [
          "948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e2262519",
          "e491a42537f6e597d5d28a3224b1bc25df9154efbd2ef1d2cbba2cae5347d57e"
        ],
        [
          "7962414450c76c1689c7b48f8202ec37fb224cf5ac0bfa1570328a8a3d7c77ab",
          "100b610ec4ffb4760d5c1fc133ef6f6b12507a051f04ac5760afa5b29db83437"
        ],
        [
          "3514087834964b54b15b160644d915485a16977225b8847bb0dd085137ec47ca",
          "ef0afbb2056205448e1652c48e8127fc6039e77c15c2378b7e7d15a0de293311"
        ],
        [
          "d3cc30ad6b483e4bc79ce2c9dd8bc54993e947eb8df787b442943d3f7b527eaf",
          "8b378a22d827278d89c5e9be8f9508ae3c2ad46290358630afb34db04eede0a4"
        ],
        [
          "1624d84780732860ce1c78fcbfefe08b2b29823db913f6493975ba0ff4847610",
          "68651cf9b6da903e0914448c6cd9d4ca896878f5282be4c8cc06e2a404078575"
        ],
        [
          "733ce80da955a8a26902c95633e62a985192474b5af207da6df7b4fd5fc61cd4",
          "f5435a2bd2badf7d485a4d8b8db9fcce3e1ef8e0201e4578c54673bc1dc5ea1d"
        ],
        [
          "15d9441254945064cf1a1c33bbd3b49f8966c5092171e699ef258dfab81c045c",
          "d56eb30b69463e7234f5137b73b84177434800bacebfc685fc37bbe9efe4070d"
        ],
        [
          "a1d0fcf2ec9de675b612136e5ce70d271c21417c9d2b8aaaac138599d0717940",
          "edd77f50bcb5a3cab2e90737309667f2641462a54070f3d519212d39c197a629"
        ],
        [
          "e22fbe15c0af8ccc5780c0735f84dbe9a790badee8245c06c7ca37331cb36980",
          "a855babad5cd60c88b430a69f53a1a7a38289154964799be43d06d77d31da06"
        ],
        [
          "311091dd9860e8e20ee13473c1155f5f69635e394704eaa74009452246cfa9b3",
          "66db656f87d1f04fffd1f04788c06830871ec5a64feee685bd80f0b1286d8374"
        ],
        [
          "34c1fd04d301be89b31c0442d3e6ac24883928b45a9340781867d4232ec2dbdf",
          "9414685e97b1b5954bd46f730174136d57f1ceeb487443dc5321857ba73abee"
        ],
        [
          "f219ea5d6b54701c1c14de5b557eb42a8d13f3abbcd08affcc2a5e6b049b8d63",
          "4cb95957e83d40b0f73af4544cccf6b1f4b08d3c07b27fb8d8c2962a400766d1"
        ],
        [
          "d7b8740f74a8fbaab1f683db8f45de26543a5490bca627087236912469a0b448",
          "fa77968128d9c92ee1010f337ad4717eff15db5ed3c049b3411e0315eaa4593b"
        ],
        [
          "32d31c222f8f6f0ef86f7c98d3a3335ead5bcd32abdd94289fe4d3091aa824bf",
          "5f3032f5892156e39ccd3d7915b9e1da2e6dac9e6f26e961118d14b8462e1661"
        ],
        [
          "7461f371914ab32671045a155d9831ea8793d77cd59592c4340f86cbc18347b5",
          "8ec0ba238b96bec0cbdddcae0aa442542eee1ff50c986ea6b39847b3cc092ff6"
        ],
        [
          "ee079adb1df1860074356a25aa38206a6d716b2c3e67453d287698bad7b2b2d6",
          "8dc2412aafe3be5c4c5f37e0ecc5f9f6a446989af04c4e25ebaac479ec1c8c1e"
        ],
        [
          "16ec93e447ec83f0467b18302ee620f7e65de331874c9dc72bfd8616ba9da6b5",
          "5e4631150e62fb40d0e8c2a7ca5804a39d58186a50e497139626778e25b0674d"
        ],
        [
          "eaa5f980c245f6f038978290afa70b6bd8855897f98b6aa485b96065d537bd99",
          "f65f5d3e292c2e0819a528391c994624d784869d7e6ea67fb18041024edc07dc"
        ],
        [
          "78c9407544ac132692ee1910a02439958ae04877151342ea96c4b6b35a49f51",
          "f3e0319169eb9b85d5404795539a5e68fa1fbd583c064d2462b675f194a3ddb4"
        ],
        [
          "494f4be219a1a77016dcd838431aea0001cdc8ae7a6fc688726578d9702857a5",
          "42242a969283a5f339ba7f075e36ba2af925ce30d767ed6e55f4b031880d562c"
        ],
        [
          "a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5",
          "204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b"
        ],
        [
          "c41916365abb2b5d09192f5f2dbeafec208f020f12570a184dbadc3e58595997",
          "4f14351d0087efa49d245b328984989d5caf9450f34bfc0ed16e96b58fa9913"
        ],
        [
          "841d6063a586fa475a724604da03bc5b92a2e0d2e0a36acfe4c73a5514742881",
          "73867f59c0659e81904f9a1c7543698e62562d6744c169ce7a36de01a8d6154"
        ],
        [
          "5e95bb399a6971d376026947f89bde2f282b33810928be4ded112ac4d70e20d5",
          "39f23f366809085beebfc71181313775a99c9aed7d8ba38b161384c746012865"
        ],
        [
          "36e4641a53948fd476c39f8a99fd974e5ec07564b5315d8bf99471bca0ef2f66",
          "d2424b1b1abe4eb8164227b085c9aa9456ea13493fd563e06fd51cf5694c78fc"
        ],
        [
          "336581ea7bfbbb290c191a2f507a41cf5643842170e914faeab27c2c579f726",
          "ead12168595fe1be99252129b6e56b3391f7ab1410cd1e0ef3dcdcabd2fda224"
        ],
        [
          "8ab89816dadfd6b6a1f2634fcf00ec8403781025ed6890c4849742706bd43ede",
          "6fdcef09f2f6d0a044e654aef624136f503d459c3e89845858a47a9129cdd24e"
        ],
        [
          "1e33f1a746c9c5778133344d9299fcaa20b0938e8acff2544bb40284b8c5fb94",
          "60660257dd11b3aa9c8ed618d24edff2306d320f1d03010e33a7d2057f3b3b6"
        ],
        [
          "85b7c1dcb3cec1b7ee7f30ded79dd20a0ed1f4cc18cbcfcfa410361fd8f08f31",
          "3d98a9cdd026dd43f39048f25a8847f4fcafad1895d7a633c6fed3c35e999511"
        ],
        [
          "29df9fbd8d9e46509275f4b125d6d45d7fbe9a3b878a7af872a2800661ac5f51",
          "b4c4fe99c775a606e2d8862179139ffda61dc861c019e55cd2876eb2a27d84b"
        ],
        [
          "a0b1cae06b0a847a3fea6e671aaf8adfdfe58ca2f768105c8082b2e449fce252",
          "ae434102edde0958ec4b19d917a6a28e6b72da1834aff0e650f049503a296cf2"
        ],
        [
          "4e8ceafb9b3e9a136dc7ff67e840295b499dfb3b2133e4ba113f2e4c0e121e5",
          "cf2174118c8b6d7a4b48f6d534ce5c79422c086a63460502b827ce62a326683c"
        ],
        [
          "d24a44e047e19b6f5afb81c7ca2f69080a5076689a010919f42725c2b789a33b",
          "6fb8d5591b466f8fc63db50f1c0f1c69013f996887b8244d2cdec417afea8fa3"
        ],
        [
          "ea01606a7a6c9cdd249fdfcfacb99584001edd28abbab77b5104e98e8e3b35d4",
          "322af4908c7312b0cfbfe369f7a7b3cdb7d4494bc2823700cfd652188a3ea98d"
        ],
        [
          "af8addbf2b661c8a6c6328655eb96651252007d8c5ea31be4ad196de8ce2131f",
          "6749e67c029b85f52a034eafd096836b2520818680e26ac8f3dfbcdb71749700"
        ],
        [
          "e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889",
          "2aeabe7e4531510116217f07bf4d07300de97e4874f81f533420a72eeb0bd6a4"
        ],
        [
          "591ee355313d99721cf6993ffed1e3e301993ff3ed258802075ea8ced397e246",
          "b0ea558a113c30bea60fc4775460c7901ff0b053d25ca2bdeee98f1a4be5d196"
        ],
        [
          "11396d55fda54c49f19aa97318d8da61fa8584e47b084945077cf03255b52984",
          "998c74a8cd45ac01289d5833a7beb4744ff536b01b257be4c5767bea93ea57a4"
        ],
        [
          "3c5d2a1ba39c5a1790000738c9e0c40b8dcdfd5468754b6405540157e017aa7a",
          "b2284279995a34e2f9d4de7396fc18b80f9b8b9fdd270f6661f79ca4c81bd257"
        ],
        [
          "cc8704b8a60a0defa3a99a7299f2e9c3fbc395afb04ac078425ef8a1793cc030",
          "bdd46039feed17881d1e0862db347f8cf395b74fc4bcdc4e940b74e3ac1f1b13"
        ],
        [
          "c533e4f7ea8555aacd9777ac5cad29b97dd4defccc53ee7ea204119b2889b197",
          "6f0a256bc5efdf429a2fb6242f1a43a2d9b925bb4a4b3a26bb8e0f45eb596096"
        ],
        [
          "c14f8f2ccb27d6f109f6d08d03cc96a69ba8c34eec07bbcf566d48e33da6593",
          "c359d6923bb398f7fd4473e16fe1c28475b740dd098075e6c0e8649113dc3a38"
        ],
        [
          "a6cbc3046bc6a450bac24789fa17115a4c9739ed75f8f21ce441f72e0b90e6ef",
          "21ae7f4680e889bb130619e2c0f95a360ceb573c70603139862afd617fa9b9f"
        ],
        [
          "347d6d9a02c48927ebfb86c1359b1caf130a3c0267d11ce6344b39f99d43cc38",
          "60ea7f61a353524d1c987f6ecec92f086d565ab687870cb12689ff1e31c74448"
        ],
        [
          "da6545d2181db8d983f7dcb375ef5866d47c67b1bf31c8cf855ef7437b72656a",
          "49b96715ab6878a79e78f07ce5680c5d6673051b4935bd897fea824b77dc208a"
        ],
        [
          "c40747cc9d012cb1a13b8148309c6de7ec25d6945d657146b9d5994b8feb1111",
          "5ca560753be2a12fc6de6caf2cb489565db936156b9514e1bb5e83037e0fa2d4"
        ],
        [
          "4e42c8ec82c99798ccf3a610be870e78338c7f713348bd34c8203ef4037f3502",
          "7571d74ee5e0fb92a7a8b33a07783341a5492144cc54bcc40a94473693606437"
        ],
        [
          "3775ab7089bc6af823aba2e1af70b236d251cadb0c86743287522a1b3b0dedea",
          "be52d107bcfa09d8bcb9736a828cfa7fac8db17bf7a76a2c42ad961409018cf7"
        ],
        [
          "cee31cbf7e34ec379d94fb814d3d775ad954595d1314ba8846959e3e82f74e26",
          "8fd64a14c06b589c26b947ae2bcf6bfa0149ef0be14ed4d80f448a01c43b1c6d"
        ],
        [
          "b4f9eaea09b6917619f6ea6a4eb5464efddb58fd45b1ebefcdc1a01d08b47986",
          "39e5c9925b5a54b07433a4f18c61726f8bb131c012ca542eb24a8ac07200682a"
        ],
        [
          "d4263dfc3d2df923a0179a48966d30ce84e2515afc3dccc1b77907792ebcc60e",
          "62dfaf07a0f78feb30e30d6295853ce189e127760ad6cf7fae164e122a208d54"
        ],
        [
          "48457524820fa65a4f8d35eb6930857c0032acc0a4a2de422233eeda897612c4",
          "25a748ab367979d98733c38a1fa1c2e7dc6cc07db2d60a9ae7a76aaa49bd0f77"
        ],
        [
          "dfeeef1881101f2cb11644f3a2afdfc2045e19919152923f367a1767c11cceda",
          "ecfb7056cf1de042f9420bab396793c0c390bde74b4bbdff16a83ae09a9a7517"
        ],
        [
          "6d7ef6b17543f8373c573f44e1f389835d89bcbc6062ced36c82df83b8fae859",
          "cd450ec335438986dfefa10c57fea9bcc521a0959b2d80bbf74b190dca712d10"
        ],
        [
          "e75605d59102a5a2684500d3b991f2e3f3c88b93225547035af25af66e04541f",
          "f5c54754a8f71ee540b9b48728473e314f729ac5308b06938360990e2bfad125"
        ],
        [
          "eb98660f4c4dfaa06a2be453d5020bc99a0c2e60abe388457dd43fefb1ed620c",
          "6cb9a8876d9cb8520609af3add26cd20a0a7cd8a9411131ce85f44100099223e"
        ],
        [
          "13e87b027d8514d35939f2e6892b19922154596941888336dc3563e3b8dba942",
          "fef5a3c68059a6dec5d624114bf1e91aac2b9da568d6abeb2570d55646b8adf1"
        ],
        [
          "ee163026e9fd6fe017c38f06a5be6fc125424b371ce2708e7bf4491691e5764a",
          "1acb250f255dd61c43d94ccc670d0f58f49ae3fa15b96623e5430da0ad6c62b2"
        ],
        [
          "b268f5ef9ad51e4d78de3a750c2dc89b1e626d43505867999932e5db33af3d80",
          "5f310d4b3c99b9ebb19f77d41c1dee018cf0d34fd4191614003e945a1216e423"
        ],
        [
          "ff07f3118a9df035e9fad85eb6c7bfe42b02f01ca99ceea3bf7ffdba93c4750d",
          "438136d603e858a3a5c440c38eccbaddc1d2942114e2eddd4740d098ced1f0d8"
        ],
        [
          "8d8b9855c7c052a34146fd20ffb658bea4b9f69e0d825ebec16e8c3ce2b526a1",
          "cdb559eedc2d79f926baf44fb84ea4d44bcf50fee51d7ceb30e2e7f463036758"
        ],
        [
          "52db0b5384dfbf05bfa9d472d7ae26dfe4b851ceca91b1eba54263180da32b63",
          "c3b997d050ee5d423ebaf66a6db9f57b3180c902875679de924b69d84a7b375"
        ],
        [
          "e62f9490d3d51da6395efd24e80919cc7d0f29c3f3fa48c6fff543becbd43352",
          "6d89ad7ba4876b0b22c2ca280c682862f342c8591f1daf5170e07bfd9ccafa7d"
        ],
        [
          "7f30ea2476b399b4957509c88f77d0191afa2ff5cb7b14fd6d8e7d65aaab1193",
          "ca5ef7d4b231c94c3b15389a5f6311e9daff7bb67b103e9880ef4bff637acaec"
        ],
        [
          "5098ff1e1d9f14fb46a210fada6c903fef0fb7b4a1dd1d9ac60a0361800b7a00",
          "9731141d81fc8f8084d37c6e7542006b3ee1b40d60dfe5362a5b132fd17ddc0"
        ],
        [
          "32b78c7de9ee512a72895be6b9cbefa6e2f3c4ccce445c96b9f2c81e2778ad58",
          "ee1849f513df71e32efc3896ee28260c73bb80547ae2275ba497237794c8753c"
        ],
        [
          "e2cb74fddc8e9fbcd076eef2a7c72b0ce37d50f08269dfc074b581550547a4f7",
          "d3aa2ed71c9dd2247a62df062736eb0baddea9e36122d2be8641abcb005cc4a4"
        ],
        [
          "8438447566d4d7bedadc299496ab357426009a35f235cb141be0d99cd10ae3a8",
          "c4e1020916980a4da5d01ac5e6ad330734ef0d7906631c4f2390426b2edd791f"
        ],
        [
          "4162d488b89402039b584c6fc6c308870587d9c46f660b878ab65c82c711d67e",
          "67163e903236289f776f22c25fb8a3afc1732f2b84b4e95dbda47ae5a0852649"
        ],
        [
          "3fad3fa84caf0f34f0f89bfd2dcf54fc175d767aec3e50684f3ba4a4bf5f683d",
          "cd1bc7cb6cc407bb2f0ca647c718a730cf71872e7d0d2a53fa20efcdfe61826"
        ],
        [
          "674f2600a3007a00568c1a7ce05d0816c1fb84bf1370798f1c69532faeb1a86b",
          "299d21f9413f33b3edf43b257004580b70db57da0b182259e09eecc69e0d38a5"
        ],
        [
          "d32f4da54ade74abb81b815ad1fb3b263d82d6c692714bcff87d29bd5ee9f08f",
          "f9429e738b8e53b968e99016c059707782e14f4535359d582fc416910b3eea87"
        ],
        [
          "30e4e670435385556e593657135845d36fbb6931f72b08cb1ed954f1e3ce3ff6",
          "462f9bce619898638499350113bbc9b10a878d35da70740dc695a559eb88db7b"
        ],
        [
          "be2062003c51cc3004682904330e4dee7f3dcd10b01e580bf1971b04d4cad297",
          "62188bc49d61e5428573d48a74e1c655b1c61090905682a0d5558ed72dccb9bc"
        ],
        [
          "93144423ace3451ed29e0fb9ac2af211cb6e84a601df5993c419859fff5df04a",
          "7c10dfb164c3425f5c71a3f9d7992038f1065224f72bb9d1d902a6d13037b47c"
        ],
        [
          "b015f8044f5fcbdcf21ca26d6c34fb8197829205c7b7d2a7cb66418c157b112c",
          "ab8c1e086d04e813744a655b2df8d5f83b3cdc6faa3088c1d3aea1454e3a1d5f"
        ],
        [
          "d5e9e1da649d97d89e4868117a465a3a4f8a18de57a140d36b3f2af341a21b52",
          "4cb04437f391ed73111a13cc1d4dd0db1693465c2240480d8955e8592f27447a"
        ],
        [
          "d3ae41047dd7ca065dbf8ed77b992439983005cd72e16d6f996a5316d36966bb",
          "bd1aeb21ad22ebb22a10f0303417c6d964f8cdd7df0aca614b10dc14d125ac46"
        ],
        [
          "463e2763d885f958fc66cdd22800f0a487197d0a82e377b49f80af87c897b065",
          "bfefacdb0e5d0fd7df3a311a94de062b26b80c61fbc97508b79992671ef7ca7f"
        ],
        [
          "7985fdfd127c0567c6f53ec1bb63ec3158e597c40bfe747c83cddfc910641917",
          "603c12daf3d9862ef2b25fe1de289aed24ed291e0ec6708703a5bd567f32ed03"
        ],
        [
          "74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9",
          "cc6157ef18c9c63cd6193d83631bbea0093e0968942e8c33d5737fd790e0db08"
        ],
        [
          "30682a50703375f602d416664ba19b7fc9bab42c72747463a71d0896b22f6da3",
          "553e04f6b018b4fa6c8f39e7f311d3176290d0e0f19ca73f17714d9977a22ff8"
        ],
        [
          "9e2158f0d7c0d5f26c3791efefa79597654e7a2b2464f52b1ee6c1347769ef57",
          "712fcdd1b9053f09003a3481fa7762e9ffd7c8ef35a38509e2fbf2629008373"
        ],
        [
          "176e26989a43c9cfeba4029c202538c28172e566e3c4fce7322857f3be327d66",
          "ed8cc9d04b29eb877d270b4878dc43c19aefd31f4eee09ee7b47834c1fa4b1c3"
        ],
        [
          "75d46efea3771e6e68abb89a13ad747ecf1892393dfc4f1b7004788c50374da8",
          "9852390a99507679fd0b86fd2b39a868d7efc22151346e1a3ca4726586a6bed8"
        ],
        [
          "809a20c67d64900ffb698c4c825f6d5f2310fb0451c869345b7319f645605721",
          "9e994980d9917e22b76b061927fa04143d096ccc54963e6a5ebfa5f3f8e286c1"
        ],
        [
          "1b38903a43f7f114ed4500b4eac7083fdefece1cf29c63528d563446f972c180",
          "4036edc931a60ae889353f77fd53de4a2708b26b6f5da72ad3394119daf408f9"
        ]
      ]
    }
  }), pa;
}
var xo;
function sn() {
  return xo || (xo = 1, (function(r) {
    var e = r, t = on(), i = As(), o = Dt(), a = o.assert;
    function p(h) {
      h.type === "short" ? this.curve = new i.short(h) : h.type === "edwards" ? this.curve = new i.edwards(h) : this.curve = new i.mont(h), this.g = this.curve.g, this.n = this.curve.n, this.hash = h.hash, a(this.g.validate(), "Invalid curve"), a(this.g.mul(this.n).isInfinity(), "Invalid curve, G*N != O");
    }
    e.PresetCurve = p;
    function c(h, m) {
      Object.defineProperty(e, h, {
        configurable: !0,
        enumerable: !0,
        get: function() {
          var S = new p(m);
          return Object.defineProperty(e, h, {
            configurable: !0,
            enumerable: !0,
            value: S
          }), S;
        }
      });
    }
    c("p192", {
      type: "short",
      prime: "p192",
      p: "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff",
      a: "ffffffff ffffffff ffffffff fffffffe ffffffff fffffffc",
      b: "64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1",
      n: "ffffffff ffffffff ffffffff 99def836 146bc9b1 b4d22831",
      hash: t.sha256,
      gRed: !1,
      g: [
        "188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012",
        "07192b95 ffc8da78 631011ed 6b24cdd5 73f977a1 1e794811"
      ]
    }), c("p224", {
      type: "short",
      prime: "p224",
      p: "ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001",
      a: "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe",
      b: "b4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4",
      n: "ffffffff ffffffff ffffffff ffff16a2 e0b8f03e 13dd2945 5c5c2a3d",
      hash: t.sha256,
      gRed: !1,
      g: [
        "b70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21",
        "bd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34"
      ]
    }), c("p256", {
      type: "short",
      prime: null,
      p: "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff",
      a: "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffc",
      b: "5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b",
      n: "ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551",
      hash: t.sha256,
      gRed: !1,
      g: [
        "6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296",
        "4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5"
      ]
    }), c("p384", {
      type: "short",
      prime: null,
      p: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 ffffffff",
      a: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 fffffffc",
      b: "b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef",
      n: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff c7634d81 f4372ddf 581a0db2 48b0a77a ecec196a ccc52973",
      hash: t.sha384,
      gRed: !1,
      g: [
        "aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7",
        "3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f"
      ]
    }), c("p521", {
      type: "short",
      prime: null,
      p: "000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff",
      a: "000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffc",
      b: "00000051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b 99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd 3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00",
      n: "000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffa 51868783 bf2f966b 7fcc0148 f709a5d0 3bb5c9b8 899c47ae bb6fb71e 91386409",
      hash: t.sha512,
      gRed: !1,
      g: [
        "000000c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139 053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127 a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66",
        "00000118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449 579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901 3fad0761 353c7086 a272c240 88be9476 9fd16650"
      ]
    }), c("curve25519", {
      type: "mont",
      prime: "p25519",
      p: "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed",
      a: "76d06",
      b: "1",
      n: "1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed",
      hash: t.sha256,
      gRed: !1,
      g: [
        "9"
      ]
    }), c("ed25519", {
      type: "edwards",
      prime: "p25519",
      p: "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed",
      a: "-1",
      c: "1",
      // -121665 * (121666^(-1)) (mod P)
      d: "52036cee2b6ffe73 8cc740797779e898 00700a4d4141d8ab 75eb4dca135978a3",
      n: "1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed",
      hash: t.sha256,
      gRed: !1,
      g: [
        "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
        // 4/5
        "6666666666666666666666666666666666666666666666666666666666666658"
      ]
    });
    var g;
    try {
      g = vc();
    } catch {
      g = void 0;
    }
    c("secp256k1", {
      type: "short",
      prime: "k256",
      p: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f",
      a: "0",
      b: "7",
      n: "ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141",
      h: "1",
      hash: t.sha256,
      // Precomputed endomorphism
      beta: "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
      lambda: "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72",
      basis: [
        {
          a: "3086d221a7d46bcde86c90e49284eb15",
          b: "-e4437ed6010e88286f547fa90abfe4c3"
        },
        {
          a: "114ca50f7a8e2f3f657c1108d9d44cfd8",
          b: "3086d221a7d46bcde86c90e49284eb15"
        }
      ],
      gRed: !1,
      g: [
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        g
      ]
    });
  })(aa)), aa;
}
var ma, ko;
function gc() {
  if (ko) return ma;
  ko = 1;
  var r = on(), e = ks(), t = Kr();
  function i(o) {
    if (!(this instanceof i))
      return new i(o);
    this.hash = o.hash, this.predResist = !!o.predResist, this.outLen = this.hash.outSize, this.minEntropy = o.minEntropy || this.hash.hmacStrength, this._reseed = null, this.reseedInterval = null, this.K = null, this.V = null;
    var a = e.toArray(o.entropy, o.entropyEnc || "hex"), p = e.toArray(o.nonce, o.nonceEnc || "hex"), c = e.toArray(o.pers, o.persEnc || "hex");
    t(
      a.length >= this.minEntropy / 8,
      "Not enough entropy. Minimum is: " + this.minEntropy + " bits"
    ), this._init(a, p, c);
  }
  return ma = i, i.prototype._init = function(a, p, c) {
    var g = a.concat(p).concat(c);
    this.K = new Array(this.outLen / 8), this.V = new Array(this.outLen / 8);
    for (var h = 0; h < this.V.length; h++)
      this.K[h] = 0, this.V[h] = 1;
    this._update(g), this._reseed = 1, this.reseedInterval = 281474976710656;
  }, i.prototype._hmac = function() {
    return new r.hmac(this.hash, this.K);
  }, i.prototype._update = function(a) {
    var p = this._hmac().update(this.V).update([0]);
    a && (p = p.update(a)), this.K = p.digest(), this.V = this._hmac().update(this.V).digest(), a && (this.K = this._hmac().update(this.V).update([1]).update(a).digest(), this.V = this._hmac().update(this.V).digest());
  }, i.prototype.reseed = function(a, p, c, g) {
    typeof p != "string" && (g = c, c = p, p = null), a = e.toArray(a, p), c = e.toArray(c, g), t(
      a.length >= this.minEntropy / 8,
      "Not enough entropy. Minimum is: " + this.minEntropy + " bits"
    ), this._update(a.concat(c || [])), this._reseed = 1;
  }, i.prototype.generate = function(a, p, c, g) {
    if (this._reseed > this.reseedInterval)
      throw new Error("Reseed is required");
    typeof p != "string" && (g = c, c = p, p = null), c && (c = e.toArray(c, g || "hex"), this._update(c));
    for (var h = []; h.length < a; )
      this.V = this._hmac().update(this.V).digest(), h = h.concat(this.V);
    var m = h.slice(0, a);
    return this._update(c), this._reseed++, e.encode(m, p);
  }, ma;
}
var ba, So;
function yc() {
  if (So) return ba;
  So = 1;
  var r = nr(), e = Dt(), t = e.assert;
  function i(o, a) {
    this.ec = o, this.priv = null, this.pub = null, a.priv && this._importPrivate(a.priv, a.privEnc), a.pub && this._importPublic(a.pub, a.pubEnc);
  }
  return ba = i, i.fromPublic = function(a, p, c) {
    return p instanceof i ? p : new i(a, {
      pub: p,
      pubEnc: c
    });
  }, i.fromPrivate = function(a, p, c) {
    return p instanceof i ? p : new i(a, {
      priv: p,
      privEnc: c
    });
  }, i.prototype.validate = function() {
    var a = this.getPublic();
    return a.isInfinity() ? { result: !1, reason: "Invalid public key" } : a.validate() ? a.mul(this.ec.curve.n).isInfinity() ? { result: !0, reason: null } : { result: !1, reason: "Public key * N != O" } : { result: !1, reason: "Public key is not a point" };
  }, i.prototype.getPublic = function(a, p) {
    return typeof a == "string" && (p = a, a = null), this.pub || (this.pub = this.ec.g.mul(this.priv)), p ? this.pub.encode(p, a) : this.pub;
  }, i.prototype.getPrivate = function(a) {
    return a === "hex" ? this.priv.toString(16, 2) : this.priv;
  }, i.prototype._importPrivate = function(a, p) {
    this.priv = new r(a, p || 16), this.priv = this.priv.umod(this.ec.curve.n);
  }, i.prototype._importPublic = function(a, p) {
    if (a.x || a.y) {
      this.ec.curve.type === "mont" ? t(a.x, "Need x coordinate") : (this.ec.curve.type === "short" || this.ec.curve.type === "edwards") && t(a.x && a.y, "Need both x and y coordinate"), this.pub = this.ec.curve.point(a.x, a.y);
      return;
    }
    this.pub = this.ec.curve.decodePoint(a, p);
  }, i.prototype.derive = function(a) {
    return a.validate() || t(a.validate(), "public point not validated"), a.mul(this.priv).getX();
  }, i.prototype.sign = function(a, p, c) {
    return this.ec.sign(a, this, p, c);
  }, i.prototype.verify = function(a, p, c) {
    return this.ec.verify(a, p, this, void 0, c);
  }, i.prototype.inspect = function() {
    return "<Key priv: " + (this.priv && this.priv.toString(16, 2)) + " pub: " + (this.pub && this.pub.inspect()) + " >";
  }, ba;
}
var va, Ao;
function wc() {
  if (Ao) return va;
  Ao = 1;
  var r = nr(), e = Dt(), t = e.assert;
  function i(g, h) {
    if (g instanceof i)
      return g;
    this._importDER(g, h) || (t(g.r && g.s, "Signature without r or s"), this.r = new r(g.r, 16), this.s = new r(g.s, 16), g.recoveryParam === void 0 ? this.recoveryParam = null : this.recoveryParam = g.recoveryParam);
  }
  va = i;
  function o() {
    this.place = 0;
  }
  function a(g, h) {
    var m = g[h.place++];
    if (!(m & 128))
      return m;
    var S = m & 15;
    if (S === 0 || S > 4 || g[h.place] === 0)
      return !1;
    for (var M = 0, I = 0, _ = h.place; I < S; I++, _++)
      M <<= 8, M |= g[_], M >>>= 0;
    return M <= 127 ? !1 : (h.place = _, M);
  }
  function p(g) {
    for (var h = 0, m = g.length - 1; !g[h] && !(g[h + 1] & 128) && h < m; )
      h++;
    return h === 0 ? g : g.slice(h);
  }
  i.prototype._importDER = function(h, m) {
    h = e.toArray(h, m);
    var S = new o();
    if (h[S.place++] !== 48)
      return !1;
    var M = a(h, S);
    if (M === !1 || M + S.place !== h.length || h[S.place++] !== 2)
      return !1;
    var I = a(h, S);
    if (I === !1 || (h[S.place] & 128) !== 0)
      return !1;
    var _ = h.slice(S.place, I + S.place);
    if (S.place += I, h[S.place++] !== 2)
      return !1;
    var E = a(h, S);
    if (E === !1 || h.length !== E + S.place || (h[S.place] & 128) !== 0)
      return !1;
    var O = h.slice(S.place, E + S.place);
    if (_[0] === 0)
      if (_[1] & 128)
        _ = _.slice(1);
      else
        return !1;
    if (O[0] === 0)
      if (O[1] & 128)
        O = O.slice(1);
      else
        return !1;
    return this.r = new r(_), this.s = new r(O), this.recoveryParam = null, !0;
  };
  function c(g, h) {
    if (h < 128) {
      g.push(h);
      return;
    }
    var m = 1 + (Math.log(h) / Math.LN2 >>> 3);
    for (g.push(m | 128); --m; )
      g.push(h >>> (m << 3) & 255);
    g.push(h);
  }
  return i.prototype.toDER = function(h) {
    var m = this.r.toArray(), S = this.s.toArray();
    for (m[0] & 128 && (m = [0].concat(m)), S[0] & 128 && (S = [0].concat(S)), m = p(m), S = p(S); !S[0] && !(S[1] & 128); )
      S = S.slice(1);
    var M = [2];
    c(M, m.length), M = M.concat(m), M.push(2), c(M, S.length);
    var I = M.concat(S), _ = [48];
    return c(_, I.length), _ = _.concat(I), e.encode(_, h);
  }, va;
}
var ga, _o;
function xc() {
  if (_o) return ga;
  _o = 1;
  var r = nr(), e = gc(), t = Dt(), i = sn(), o = Ss(), a = t.assert, p = yc(), c = wc();
  function g(h) {
    if (!(this instanceof g))
      return new g(h);
    typeof h == "string" && (a(
      Object.prototype.hasOwnProperty.call(i, h),
      "Unknown curve " + h
    ), h = i[h]), h instanceof i.PresetCurve && (h = { curve: h }), this.curve = h.curve.curve, this.n = this.curve.n, this.nh = this.n.ushrn(1), this.g = this.curve.g, this.g = h.curve.g, this.g.precompute(h.curve.n.bitLength() + 1), this.hash = h.hash || h.curve.hash;
  }
  return ga = g, g.prototype.keyPair = function(m) {
    return new p(this, m);
  }, g.prototype.keyFromPrivate = function(m, S) {
    return p.fromPrivate(this, m, S);
  }, g.prototype.keyFromPublic = function(m, S) {
    return p.fromPublic(this, m, S);
  }, g.prototype.genKeyPair = function(m) {
    m || (m = {});
    for (var S = new e({
      hash: this.hash,
      pers: m.pers,
      persEnc: m.persEnc || "utf8",
      entropy: m.entropy || o(this.hash.hmacStrength),
      entropyEnc: m.entropy && m.entropyEnc || "utf8",
      nonce: this.n.toArray()
    }), M = this.n.byteLength(), I = this.n.sub(new r(2)); ; ) {
      var _ = new r(S.generate(M));
      if (!(_.cmp(I) > 0))
        return _.iaddn(1), this.keyFromPrivate(_);
    }
  }, g.prototype._truncateToN = function(m, S, M) {
    var I;
    if (r.isBN(m) || typeof m == "number")
      m = new r(m, 16), I = m.byteLength();
    else if (typeof m == "object")
      I = m.length, m = new r(m, 16);
    else {
      var _ = m.toString();
      I = _.length + 1 >>> 1, m = new r(_, 16);
    }
    typeof M != "number" && (M = I * 8);
    var E = M - this.n.bitLength();
    return E > 0 && (m = m.ushrn(E)), !S && m.cmp(this.n) >= 0 ? m.sub(this.n) : m;
  }, g.prototype.sign = function(m, S, M, I) {
    if (typeof M == "object" && (I = M, M = null), I || (I = {}), typeof m != "string" && typeof m != "number" && !r.isBN(m)) {
      a(
        typeof m == "object" && m && typeof m.length == "number",
        "Expected message to be an array-like, a hex string, or a BN instance"
      ), a(m.length >>> 0 === m.length);
      for (var _ = 0; _ < m.length; _++) a((m[_] & 255) === m[_]);
    }
    S = this.keyFromPrivate(S, M), m = this._truncateToN(m, !1, I.msgBitLength), a(!m.isNeg(), "Can not sign a negative message");
    var E = this.n.byteLength(), O = S.getPrivate().toArray("be", E), N = m.toArray("be", E);
    a(new r(N).eq(m), "Can not sign message");
    for (var U = new e({
      hash: this.hash,
      entropy: O,
      nonce: N,
      pers: I.pers,
      persEnc: I.persEnc || "utf8"
    }), j = this.n.sub(new r(1)), F = 0; ; F++) {
      var C = I.k ? I.k(F) : new r(U.generate(this.n.byteLength()));
      if (C = this._truncateToN(C, !0), !(C.cmpn(1) <= 0 || C.cmp(j) >= 0)) {
        var q = this.g.mul(C);
        if (!q.isInfinity()) {
          var V = q.getX(), Z = V.umod(this.n);
          if (Z.cmpn(0) !== 0) {
            var K = C.invm(this.n).mul(Z.mul(S.getPrivate()).iadd(m));
            if (K = K.umod(this.n), K.cmpn(0) !== 0) {
              var G = (q.getY().isOdd() ? 1 : 0) | (V.cmp(Z) !== 0 ? 2 : 0);
              return I.canonical && K.cmp(this.nh) > 0 && (K = this.n.sub(K), G ^= 1), new c({ r: Z, s: K, recoveryParam: G });
            }
          }
        }
      }
    }
  }, g.prototype.verify = function(m, S, M, I, _) {
    _ || (_ = {}), m = this._truncateToN(m, !1, _.msgBitLength), M = this.keyFromPublic(M, I), S = new c(S, "hex");
    var E = S.r, O = S.s;
    if (E.cmpn(1) < 0 || E.cmp(this.n) >= 0 || O.cmpn(1) < 0 || O.cmp(this.n) >= 0)
      return !1;
    var N = O.invm(this.n), U = N.mul(m).umod(this.n), j = N.mul(E).umod(this.n), F;
    return this.curve._maxwellTrick ? (F = this.g.jmulAdd(U, M.getPublic(), j), F.isInfinity() ? !1 : F.eqXToP(E)) : (F = this.g.mulAdd(U, M.getPublic(), j), F.isInfinity() ? !1 : F.getX().umod(this.n).cmp(E) === 0);
  }, g.prototype.recoverPubKey = function(h, m, S, M) {
    a((3 & S) === S, "The recovery param is more than two bits"), m = new c(m, M);
    var I = this.n, _ = new r(h), E = m.r, O = m.s, N = S & 1, U = S >> 1;
    if (E.cmp(this.curve.p.umod(this.curve.n)) >= 0 && U)
      throw new Error("Unable to find sencond key candinate");
    U ? E = this.curve.pointFromX(E.add(this.curve.n), N) : E = this.curve.pointFromX(E, N);
    var j = m.r.invm(I), F = I.sub(_).mul(j).umod(I), C = O.mul(j).umod(I);
    return this.g.mulAdd(F, E, C);
  }, g.prototype.getKeyRecoveryParam = function(h, m, S, M) {
    if (m = new c(m, M), m.recoveryParam !== null)
      return m.recoveryParam;
    for (var I = 0; I < 4; I++) {
      var _;
      try {
        _ = this.recoverPubKey(h, m, I);
      } catch {
        continue;
      }
      if (_.eq(S))
        return I;
    }
    throw new Error("Unable to find valid recovery factor");
  }, ga;
}
var ya, Mo;
function kc() {
  if (Mo) return ya;
  Mo = 1;
  var r = Dt(), e = r.assert, t = r.parseBytes, i = r.cachedProperty;
  function o(a, p) {
    this.eddsa = a, this._secret = t(p.secret), a.isPoint(p.pub) ? this._pub = p.pub : this._pubBytes = t(p.pub);
  }
  return o.fromPublic = function(p, c) {
    return c instanceof o ? c : new o(p, { pub: c });
  }, o.fromSecret = function(p, c) {
    return c instanceof o ? c : new o(p, { secret: c });
  }, o.prototype.secret = function() {
    return this._secret;
  }, i(o, "pubBytes", function() {
    return this.eddsa.encodePoint(this.pub());
  }), i(o, "pub", function() {
    return this._pubBytes ? this.eddsa.decodePoint(this._pubBytes) : this.eddsa.g.mul(this.priv());
  }), i(o, "privBytes", function() {
    var p = this.eddsa, c = this.hash(), g = p.encodingLength - 1, h = c.slice(0, p.encodingLength);
    return h[0] &= 248, h[g] &= 127, h[g] |= 64, h;
  }), i(o, "priv", function() {
    return this.eddsa.decodeInt(this.privBytes());
  }), i(o, "hash", function() {
    return this.eddsa.hash().update(this.secret()).digest();
  }), i(o, "messagePrefix", function() {
    return this.hash().slice(this.eddsa.encodingLength);
  }), o.prototype.sign = function(p) {
    return e(this._secret, "KeyPair can only verify"), this.eddsa.sign(p, this);
  }, o.prototype.verify = function(p, c) {
    return this.eddsa.verify(p, c, this);
  }, o.prototype.getSecret = function(p) {
    return e(this._secret, "KeyPair is public only"), r.encode(this.secret(), p);
  }, o.prototype.getPublic = function(p) {
    return r.encode(this.pubBytes(), p);
  }, ya = o, ya;
}
var wa, Bo;
function Sc() {
  if (Bo) return wa;
  Bo = 1;
  var r = nr(), e = Dt(), t = e.assert, i = e.cachedProperty, o = e.parseBytes;
  function a(p, c) {
    this.eddsa = p, typeof c != "object" && (c = o(c)), Array.isArray(c) && (t(c.length === p.encodingLength * 2, "Signature has invalid size"), c = {
      R: c.slice(0, p.encodingLength),
      S: c.slice(p.encodingLength)
    }), t(c.R && c.S, "Signature without R or S"), p.isPoint(c.R) && (this._R = c.R), c.S instanceof r && (this._S = c.S), this._Rencoded = Array.isArray(c.R) ? c.R : c.Rencoded, this._Sencoded = Array.isArray(c.S) ? c.S : c.Sencoded;
  }
  return i(a, "S", function() {
    return this.eddsa.decodeInt(this.Sencoded());
  }), i(a, "R", function() {
    return this.eddsa.decodePoint(this.Rencoded());
  }), i(a, "Rencoded", function() {
    return this.eddsa.encodePoint(this.R());
  }), i(a, "Sencoded", function() {
    return this.eddsa.encodeInt(this.S());
  }), a.prototype.toBytes = function() {
    return this.Rencoded().concat(this.Sencoded());
  }, a.prototype.toHex = function() {
    return e.encode(this.toBytes(), "hex").toUpperCase();
  }, wa = a, wa;
}
var xa, Io;
function Ac() {
  if (Io) return xa;
  Io = 1;
  var r = on(), e = sn(), t = Dt(), i = t.assert, o = t.parseBytes, a = kc(), p = Sc();
  function c(g) {
    if (i(g === "ed25519", "only tested with ed25519 so far"), !(this instanceof c))
      return new c(g);
    g = e[g].curve, this.curve = g, this.g = g.g, this.g.precompute(g.n.bitLength() + 1), this.pointClass = g.point().constructor, this.encodingLength = Math.ceil(g.n.bitLength() / 8), this.hash = r.sha512;
  }
  return xa = c, c.prototype.sign = function(h, m) {
    h = o(h);
    var S = this.keyFromSecret(m), M = this.hashInt(S.messagePrefix(), h), I = this.g.mul(M), _ = this.encodePoint(I), E = this.hashInt(_, S.pubBytes(), h).mul(S.priv()), O = M.add(E).umod(this.curve.n);
    return this.makeSignature({ R: I, S: O, Rencoded: _ });
  }, c.prototype.verify = function(h, m, S) {
    if (h = o(h), m = this.makeSignature(m), m.S().gte(m.eddsa.curve.n) || m.S().isNeg())
      return !1;
    var M = this.keyFromPublic(S), I = this.hashInt(m.Rencoded(), M.pubBytes(), h), _ = this.g.mul(m.S()), E = m.R().add(M.pub().mul(I));
    return E.eq(_);
  }, c.prototype.hashInt = function() {
    for (var h = this.hash(), m = 0; m < arguments.length; m++)
      h.update(arguments[m]);
    return t.intFromLE(h.digest()).umod(this.curve.n);
  }, c.prototype.keyFromPublic = function(h) {
    return a.fromPublic(this, h);
  }, c.prototype.keyFromSecret = function(h) {
    return a.fromSecret(this, h);
  }, c.prototype.makeSignature = function(h) {
    return h instanceof p ? h : new p(this, h);
  }, c.prototype.encodePoint = function(h) {
    var m = h.getY().toArray("le", this.encodingLength);
    return m[this.encodingLength - 1] |= h.getX().isOdd() ? 128 : 0, m;
  }, c.prototype.decodePoint = function(h) {
    h = t.parseBytes(h);
    var m = h.length - 1, S = h.slice(0, m).concat(h[m] & -129), M = (h[m] & 128) !== 0, I = t.intFromLE(S);
    return this.curve.pointFromY(I, M);
  }, c.prototype.encodeInt = function(h) {
    return h.toArray("le", this.encodingLength);
  }, c.prototype.decodeInt = function(h) {
    return t.intFromLE(h);
  }, c.prototype.isPoint = function(h) {
    return h instanceof this.pointClass;
  }, xa;
}
var Eo;
function _c() {
  return Eo || (Eo = 1, (function(r) {
    var e = r;
    e.version = oc.version, e.utils = Dt(), e.rand = Ss(), e.curve = As(), e.curves = sn(), e.ec = xc(), e.eddsa = Ac();
  })(Yi)), Yi;
}
var Mc = _c();
const Bc = /* @__PURE__ */ Fi(Mc);
function Ic(r) {
  if (r.length >= 255)
    throw new TypeError("Alphabet too long");
  const e = new Uint8Array(256);
  for (let h = 0; h < e.length; h++)
    e[h] = 255;
  for (let h = 0; h < r.length; h++) {
    const m = r.charAt(h), S = m.charCodeAt(0);
    if (e[S] !== 255)
      throw new TypeError(m + " is ambiguous");
    e[S] = h;
  }
  const t = r.length, i = r.charAt(0), o = Math.log(t) / Math.log(256), a = Math.log(256) / Math.log(t);
  function p(h) {
    if (h instanceof Uint8Array || (ArrayBuffer.isView(h) ? h = new Uint8Array(h.buffer, h.byteOffset, h.byteLength) : Array.isArray(h) && (h = Uint8Array.from(h))), !(h instanceof Uint8Array))
      throw new TypeError("Expected Uint8Array");
    if (h.length === 0)
      return "";
    let m = 0, S = 0, M = 0;
    const I = h.length;
    for (; M !== I && h[M] === 0; )
      M++, m++;
    const _ = (I - M) * a + 1 >>> 0, E = new Uint8Array(_);
    for (; M !== I; ) {
      let U = h[M], j = 0;
      for (let F = _ - 1; (U !== 0 || j < S) && F !== -1; F--, j++)
        U += 256 * E[F] >>> 0, E[F] = U % t >>> 0, U = U / t >>> 0;
      if (U !== 0)
        throw new Error("Non-zero carry");
      S = j, M++;
    }
    let O = _ - S;
    for (; O !== _ && E[O] === 0; )
      O++;
    let N = i.repeat(m);
    for (; O < _; ++O)
      N += r.charAt(E[O]);
    return N;
  }
  function c(h) {
    if (typeof h != "string")
      throw new TypeError("Expected String");
    if (h.length === 0)
      return new Uint8Array();
    let m = 0, S = 0, M = 0;
    for (; h[m] === i; )
      S++, m++;
    const I = (h.length - m) * o + 1 >>> 0, _ = new Uint8Array(I);
    for (; m < h.length; ) {
      const U = h.charCodeAt(m);
      if (U > 255)
        return;
      let j = e[U];
      if (j === 255)
        return;
      let F = 0;
      for (let C = I - 1; (j !== 0 || F < M) && C !== -1; C--, F++)
        j += t * _[C] >>> 0, _[C] = j % 256 >>> 0, j = j / 256 >>> 0;
      if (j !== 0)
        throw new Error("Non-zero carry");
      M = F, m++;
    }
    let E = I - M;
    for (; E !== I && _[E] === 0; )
      E++;
    const O = new Uint8Array(S + (I - E));
    let N = S;
    for (; E !== I; )
      O[N++] = _[E++];
    return O;
  }
  function g(h) {
    const m = c(h);
    if (m)
      return m;
    throw new Error("Non-base" + t + " character");
  }
  return {
    encode: p,
    decodeUnsafe: c,
    decode: g
  };
}
var Ec = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const Po = Ic(Ec);
var Is = globalThis, un = {};
un = JSON.parse('{"name":"libnexa-ts","version":"1.0.6","description":"A pure and powerful Nexa SDK library.","type":"module","source":"src/index.ts","types":"dist/index.d.ts","main":"dist/index.cjs","module":"dist/index.mjs","browser":"dist/index.web.mjs","exports":{"types":"./dist/index.d.ts","node":{"import":"./dist/index.mjs","require":"./dist/index.cjs"},"browser":"./dist/index.web.mjs","default":"./dist/index.mjs"},"targets":{"main":{"context":"node","outputFormat":"commonjs","distDir":"dist","isLibrary":true,"includeNodeModules":["lodash-es"]},"module":{"context":"node","outputFormat":"esmodule","distDir":"dist","isLibrary":true},"browser":{"context":"browser","outputFormat":"esmodule","distDir":"dist","isLibrary":true}},"files":["dist"],"scripts":{"check":"tsc --noEmit && npm run madge","build":"del-cli ./dist && parcel build","lint":"eslint .","madge":"madge --circular src/index.ts","test":"vitest run --dir tests","coverage":"del-cli ./coverage && npm test -- --coverage --reporter=verbose --reporter=junit","docs":"typedoc"},"keywords":["nexa","blockchain"],"repository":{"type":"git","url":"https://gitlab.com/nexa/libnexa-ts"},"author":"vgrunner","license":"MIT","dependencies":{"bn.js":"^5.2.2","bs58":"^6.0.0","elliptic":"^6.6.1","js-big-decimal":"^2.2.0","lodash-es":"^4.17.21"},"devDependencies":{"@parcel/packager-ts":"^2.15.4","@parcel/transformer-typescript-types":"^2.15.4","@types/bn.js":"^5.2.0","@types/elliptic":"^6.4.18","@types/lodash-es":"^4.17.12","@types/node":"^24.0.8","@vitest/coverage-v8":"^3.2.4","del-cli":"^6.0.0","eslint":"^9.30.0","madge":"^8.0.0","parcel":"^2.15.4","typedoc":"^0.28.7","typedoc-plugin-markdown":"^4.7.0","typedoc-plugin-rename-defaults":"^0.7.3","typescript":"^5.8.3","typescript-eslint":"^8.35.1","vitest":"^3.0.6"},"@parcel/resolver-default":{"packageExports":true},"madge":{"detectiveOptions":{"ts":{"skipTypeImports":true}}}}');
class R {
  static validateState(e, t) {
    if (!e) throw new Error(`Invalid State: ${t}`);
  }
  static validateArgument(e, t, i = "") {
    if (!e) throw new Error(`Invalid Argument: ${t}. ${i}`);
  }
  static validateArgumentType(e, t, i) {
    if (i = i || "(unknown name)", te(t)) {
      if (t === "Buffer") {
        if (!Buffer.isBuffer(e)) throw new TypeError(`Invalid Argument for ${i}, expected ${t} but got ${typeof e}`);
      } else if (typeof e !== t) throw new TypeError(`Invalid Argument for ${i}, expected ${t} but got ${typeof e}`);
    } else if (!(e instanceof t)) throw new TypeError(`Invalid Argument for ${i}, expected ${t} but got ${typeof e}`);
  }
}
class W {
  /**
  * Fill a buffer with a value.
  *
  * @param buffer
  * @param value
  * @return filled buffer
  * 
  * @deprecated use `buffer.fill(value)`
  */
  static fill(e, t) {
    return R.validateArgumentType(e, "Buffer", "buffer"), R.validateArgumentType(t, "number", "value"), e.fill(t);
  }
  /**
  *
  * @param original buffer
  * @return Return a copy of a buffer
  * 
  * @deprecated use `Buffer.from(original) or Buffer.copyBytesFrom(original)`
  */
  static copy(e) {
    let t = Buffer.alloc(e.length);
    return e.copy(t), t;
  }
  /**
  * Tests for both node's Buffer and Uint8Array
  *
  * @param arg
  * @return Returns true if the given argument is an instance of a buffer. 
  */
  static isBuffer(e) {
    return Buffer.isBuffer(e) || e instanceof Uint8Array;
  }
  /**
  * Tests for both node's Buffer and Uint8Array
  *
  * @param arg
  * @return Returns true if the given argument is an instance of a hash160 or hash256 buffer. 
  */
  static isHashBuffer(e) {
    return this.isBuffer(e) && (e.length === 20 || e.length === 32);
  }
  /**
  * Returns a zero-filled byte array
  *
  * @param length
  * 
  * @deprecated use `Buffer.alloc(length)`
  */
  static emptyBuffer(e) {
    return R.validateArgumentType(e, "number", "length"), Buffer.alloc(e);
  }
  /**
  * Reverse a buffer
  * @param param
  * @return new reversed buffer
  */
  static reverse(e) {
    return Buffer.from(e).reverse();
  }
  /**
  * Transforms a buffer into a string with a number in hexa representation
  *
  * Shorthand for <tt>buffer.toString('hex')</tt>
  *
  * @param buffer
  * @return string
  */
  static bufferToHex(e) {
    return R.validateArgumentType(e, "Buffer", "buffer"), e.toString("hex");
  }
  /**
  * Transforms a number from 0 to 255 into a Buffer of size 1 with that value
  *
  * @param integer
  * @return Buffer
  */
  static integerAsSingleByteBuffer(e) {
    return R.validateArgumentType(e, "number", "integer"), Buffer.from([
      e & 255
    ]);
  }
  /**
  * Transforms the first byte of an array into a number ranging from -128 to 127
  * 
  * @param buffer
  * @return number
  */
  static integerFromSingleByteBuffer(e) {
    return R.validateArgumentType(e, "Buffer", "buffer"), e[0];
  }
  /**
  * Transform a 4-byte integer into a Buffer of length 4.
  *
  * @param integer
  * @return Buffer
  */
  static integerAsBuffer(e) {
    R.validateArgumentType(e, "number", "integer");
    let t = [];
    return t.push(e >> 24 & 255), t.push(e >> 16 & 255), t.push(e >> 8 & 255), t.push(e & 255), Buffer.from(t);
  }
  /**
  * Transform the first 4 values of a Buffer into a number, in little endian encoding
  *
  * @param buffer
  * @return integer
  */
  static integerFromBuffer(e) {
    return R.validateArgumentType(e, "Buffer", "buffer"), e[0] << 24 | e[1] << 16 | e[2] << 8 | e[3];
  }
  /* secure random bytes that sometimes throws an error due to lack of entropy */
  static getRandomBuffer(e) {
    return Yt.randomBytes(e);
  }
}
class le {
  static sha1(e) {
    return R.validateArgument(W.isBuffer(e), "buf", "Must be Buffer"), Yt.createHash("sha1").update(e).digest();
  }
  static sha256(e) {
    return R.validateArgument(W.isBuffer(e), "buf", "Must be Buffer"), Yt.createHash("sha256").update(e).digest();
  }
  static sha512(e) {
    return R.validateArgument(W.isBuffer(e), "buf", "Must be Buffer"), Yt.createHash("sha512").update(e).digest();
  }
  static ripemd160(e) {
    return R.validateArgument(W.isBuffer(e), "buf", "Must be Buffer"), Yt.createHash("ripemd160").update(e).digest();
  }
  static sha256sha256(e) {
    return R.validateArgument(W.isBuffer(e), "buf", "Must be Buffer"), this.sha256(this.sha256(e));
  }
  static sha256ripemd160(e) {
    return R.validateArgument(W.isBuffer(e), "buf", "Must be Buffer"), this.ripemd160(this.sha256(e));
  }
  static sha256hmac(e, t) {
    return le.hmac(le.sha256, 512, e, t);
  }
  static sha512hmac(e, t) {
    return le.hmac(le.sha512, 1024, e, t);
  }
  static hmac(e, t, i, o) {
    R.validateArgument(W.isBuffer(i), "data", "Must be Buffer"), R.validateArgument(W.isBuffer(o), "key", "Must be Buffer");
    let a = t / 8;
    if (o.length > a) o = e(o);
    else if (o.length < a) {
      let m = Buffer.alloc(a);
      m.fill(0), o.copy(m), o = m;
    }
    let p = Buffer.alloc(a);
    p.fill(92);
    let c = Buffer.alloc(a);
    c.fill(54);
    let g = Buffer.alloc(a), h = Buffer.alloc(a);
    for (let m = 0; m < a; m++)
      g[m] = p[m] ^ o[m], h[m] = c[m] ^ o[m];
    return e(Buffer.concat([
      g,
      e(Buffer.concat([
        h,
        i
      ]))
    ]));
  }
}
class vt {
  /**
  * Determines whether a string contains only hexadecimal values
  * 
  * @param value
  * @returns true if the string is the hexa representation of a number
  */
  static isHexa(e) {
    return te(e) && e.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(e);
  }
  /**
  * Test if an argument is a valid JSON object. If it is, returns a truthy
  * value (the json object decoded), so no double JSON.parse call is necessary
  *
  * @param arg
  * @return false if the argument is not a JSON string.
  */
  static isValidJSON(e) {
    if (!te(e)) return !1;
    try {
      return JSON.parse(e);
    } catch {
      return !1;
    }
  }
  static cloneArray(e) {
    return [
      ...e
    ];
  }
  /**
  * Checks that a value is a natural number.
  *
  * @param value
  * @return true if a positive integer or zero.
  */
  static isNaturalNumber(e) {
    return typeof e == "number" && isFinite(e) && Math.floor(e) === e && e >= 0;
  }
  /**
  * Checks that a value is a natural number.
  *
  * @param value
  * @return true if a positive integer or zero.
  */
  static isNaturalBigInt(e) {
    return typeof e == "bigint" && e >= 0n;
  }
}
class X extends ic {
  static {
    this.Zero = new X(0);
  }
  static {
    this.One = new X(1);
  }
  static {
    this.Minus1 = new X(-1);
  }
  static fromNumber(e) {
    return R.validateArgument(Tt(e), "num"), new X(e);
  }
  static fromBigInt(e) {
    return R.validateArgument(typeof e == "bigint", "num"), new X(e.toString());
  }
  static fromString(e, t) {
    return R.validateArgument(te(e), "str"), new X(e, t);
  }
  static fromBuffer(e, t) {
    return R.validateArgument(W.isBuffer(e), "buf"), t?.endian === "little" && (e = W.reverse(e)), new X(e.toString("hex"), 16);
  }
  /**
  * Create a BN from a "ScriptNum":
  * This is analogous to the constructor for CScriptNum in nexad. Many ops in
  * nexad's script interpreter use CScriptNum, which is not really a proper
  * bignum. Instead, an error is thrown if trying to input a number bigger than
  * 4 bytes. We copy that behavior here. A third argument, `size`, is provided to
  * extend the hard limit of 4 bytes, as some usages require more than 4 bytes.
  */
  static fromScriptNumBuffer(e, t, i) {
    let o = i || 4;
    if (R.validateArgument(e.length <= o, "script number overflow"), t && e.length > 0 && (e[e.length - 1] & 127) === 0 && (e.length <= 1 || (e[e.length - 2] & 128) === 0))
      throw new Error("non-minimally encoded script number");
    return X.fromSM(e, {
      endian: "little"
    });
  }
  // Override arithmetic methods to ensure they return BNExtended instances
  add(e) {
    const t = super.add(e).toString();
    return new X(t);
  }
  sub(e) {
    const t = super.sub(e).toString();
    return new X(t);
  }
  mul(e) {
    const t = super.mul(e).toString();
    return new X(t);
  }
  mod(e) {
    const t = super.mod(e).toString();
    return new X(t);
  }
  umod(e) {
    const t = super.umod(e).toString();
    return new X(t);
  }
  toNumber() {
    return parseInt(this.toString(10), 10);
  }
  toBigInt() {
    return BigInt(this.toString(10));
  }
  toBuffer(e, t) {
    if (te(e))
      return super.toBuffer(e, t);
    let i = this.toString(16, 2), o = Buffer.from(i, "hex");
    if (e?.size) {
      let a = i.length / 2;
      a > e.size ? o = X.trim(o, a) : a < e.size && (o = X.pad(o, a, e.size));
    }
    return e?.endian === "little" && (o = W.reverse(o)), o;
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
      bignum: !0
    });
  }
  getSize() {
    return (this.toString(2).replace("-", "").length + 1) / 8;
  }
  safeAdd(e, t) {
    const i = this.add(e);
    return this.checkOperationForOverflow(e, i, t), i;
  }
  safeSub(e, t) {
    const i = this.sub(e);
    return this.checkOperationForOverflow(e, i, t), i;
  }
  safeMul(e, t) {
    const i = this.mul(e);
    return this.checkOperationForOverflow(e, i, t), i;
  }
  checkOperationForOverflow(e, t, i) {
    if (this.getSize() > i || e.getSize() > i || t.getSize() > 8) throw new Error("overflow");
  }
  toSMBigEndian() {
    let e;
    return this.cmp(X.Zero) === -1 ? (e = this.neg().toBuffer(), e[0] & 128 ? e = Buffer.concat([
      Buffer.from([
        128
      ]),
      e
    ]) : e[0] = e[0] | 128) : (e = this.toBuffer(), e[0] & 128 && (e = Buffer.concat([
      Buffer.from([
        0
      ]),
      e
    ]))), e.length === 1 && e[0] === 0 && (e = Buffer.from([])), e;
  }
  toBigNumSMBigEndian() {
    let e;
    return this.cmp(X.Zero) === -1 ? (e = this.neg().toBuffer(), e = Buffer.concat([
      Buffer.from([
        128
      ]),
      e
    ])) : (e = this.toBuffer(), e = Buffer.concat([
      Buffer.from([
        0
      ]),
      e
    ])), e;
  }
  toSM(e) {
    let t = e?.bignum ? this.toBigNumSMBigEndian() : this.toSMBigEndian();
    return e?.endian === "little" && (t = W.reverse(t)), t;
  }
  /**
  * Instantiate a BigNumber from a "signed magnitude buffer"
  * (a buffer where the most significant bit represents the sign (0 = positive, -1 = negative))
  */
  static fromSM(e, t) {
    if (e.length === 0) return this.fromBuffer(Buffer.from([
      0
    ]));
    t?.endian === "little" && (e = W.reverse(e));
    let i;
    return e[0] & 128 ? (e[0] = e[0] & 127, i = this.fromBuffer(e), i.neg().copy(i)) : i = this.fromBuffer(e), i;
  }
  static trim(e, t) {
    return e.subarray(t - e.length, t);
  }
  static pad(e, t, i) {
    let o = Buffer.alloc(i);
    for (let a = 0; a < e.length; a++) o[o.length - 1 - a] = e[e.length - 1 - a];
    for (let a = 0; a < i - t; a++) o[a] = 0;
    return o;
  }
}
class Ui {
  constructor(e) {
    if (this.finished = this.eof, this.buf = Buffer.from([]), this.pos = 0, !oe(e))
      if (Buffer.isBuffer(e)) this.set({
        buf: e
      });
      else if (te(e)) {
        let t = Buffer.from(e, "hex");
        if (t.length * 2 != e.length) throw new TypeError("Invalid hex string");
        this.set({
          buf: t
        });
      } else if (Oe(e)) {
        let t = e;
        this.set(t);
      } else throw new TypeError("Unrecognized argument for BufferReader");
  }
  set(e) {
    return this.buf = e.buf || this.buf, this.pos = e.pos || this.pos || 0, this;
  }
  eof() {
    return this.pos >= this.buf.length;
  }
  read(e) {
    R.validateArgument(!oe(e), "Must specify a length");
    let t = this.buf.subarray(this.pos, this.pos + e);
    return this.pos = this.pos + e, t;
  }
  readAll() {
    let e = this.buf.subarray(this.pos, this.buf.length);
    return this.pos = this.buf.length, e;
  }
  readUInt8() {
    let e = this.buf.readUInt8(this.pos);
    return this.pos = this.pos + 1, e;
  }
  readUInt16BE() {
    let e = this.buf.readUInt16BE(this.pos);
    return this.pos = this.pos + 2, e;
  }
  readUInt16LE() {
    let e = this.buf.readUInt16LE(this.pos);
    return this.pos = this.pos + 2, e;
  }
  readUInt32BE() {
    let e = this.buf.readUInt32BE(this.pos);
    return this.pos = this.pos + 4, e;
  }
  readUInt32LE() {
    let e = this.buf.readUInt32LE(this.pos);
    return this.pos = this.pos + 4, e;
  }
  readInt32LE() {
    let e = this.buf.readInt32LE(this.pos);
    return this.pos = this.pos + 4, e;
  }
  readUInt64BEBN() {
    let e = this.buf.subarray(this.pos, this.pos + 8), t = X.fromBuffer(e);
    return this.pos = this.pos + 8, t;
  }
  readUInt64LEBN() {
    let e = this.buf.readUInt32LE(this.pos), i = this.buf.readUInt32LE(this.pos + 4) * 4294967296 + e, o;
    if (i <= 9007199254740991) o = new X(i);
    else {
      let a = this.buf.subarray(this.pos, this.pos + 8);
      o = new X(a, 10, "le");
    }
    return this.pos = this.pos + 8, o;
  }
  readVarintNum() {
    let e = this.readUInt8();
    switch (e) {
      case 253:
        return this.readUInt16LE();
      case 254:
        return this.readUInt32LE();
      case 255:
        let i = this.readUInt64LEBN().toNumber();
        if (i <= Math.pow(2, 53)) return i;
        throw new Error("number too large to retain precision - use readVarintBN");
    }
    return e;
  }
  /**
  * reads a length prepended buffer
  */
  readVarLengthBuffer() {
    let e = this.readVarintNum(), t = this.read(e);
    return R.validateState(t.length === e, "Invalid length while reading varlength buffer. Expected to read: " + e + " and read " + t.length), t;
  }
  readVarintBuf() {
    switch (this.buf.readUInt8(this.pos)) {
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
    let e = this.readUInt8();
    switch (e) {
      case 253:
        return new X(this.readUInt16LE());
      case 254:
        return new X(this.readUInt32LE());
      case 255:
        return this.readUInt64LEBN();
      default:
        return new X(e);
    }
  }
  reverse() {
    let e = W.reverse(this.buf);
    return this.buf = e, this;
  }
  readReverse(e) {
    oe(e) && (e = this.buf.length);
    let t = this.buf.subarray(this.pos, this.pos + e);
    return this.pos = this.pos + e, W.reverse(t);
  }
  readCoreVarintNum() {
    let e = 0;
    for (; ; ) {
      let t = this.readUInt8();
      if (e = e << 7 | t & 127, t & 128) e++;
      else return e;
    }
  }
}
class Je {
  constructor(e) {
    this.bufs = [], this.bufLen = 0, e && this.set(e);
  }
  set(e) {
    return this.bufs = e.bufs || this.bufs, this.bufLen = this.bufs.reduce((t, i) => t + i.length, 0), this;
  }
  toBuffer() {
    return this.concat();
  }
  concat() {
    return Buffer.concat(this.bufs, this.bufLen);
  }
  write(e) {
    return R.validateArgument(W.isBuffer(e), "buf"), this.bufs.push(e), this.bufLen += e.length, this;
  }
  writeReverse(e) {
    return R.validateArgument(W.isBuffer(e), "buf"), this.bufs.push(W.reverse(e)), this.bufLen += e.length, this;
  }
  writeUInt8(e) {
    let t = Buffer.alloc(1);
    return t.writeUInt8(e, 0), this.write(t), this;
  }
  writeUInt16BE(e) {
    let t = Buffer.alloc(2);
    return t.writeUInt16BE(e, 0), this.write(t), this;
  }
  writeUInt16LE(e) {
    let t = Buffer.alloc(2);
    return t.writeUInt16LE(e, 0), this.write(t), this;
  }
  writeUInt32BE(e) {
    let t = Buffer.alloc(4);
    return t.writeUInt32BE(e, 0), this.write(t), this;
  }
  writeInt32LE(e) {
    let t = Buffer.alloc(4);
    return t.writeInt32LE(e, 0), this.write(t), this;
  }
  writeUInt32LE(e) {
    let t = Buffer.alloc(4);
    return t.writeUInt32LE(e, 0), this.write(t), this;
  }
  writeUInt64BEBN(e) {
    let t = e.toBuffer({
      size: 8
    });
    return this.write(t), this;
  }
  writeUInt64LEBN(e) {
    let t = e.toBuffer({
      size: 8
    });
    return this.writeReverse(t), this;
  }
  writeVarintNum(e) {
    let t = Je.varintBufNum(e);
    return this.write(t), this;
  }
  writeVarintBN(e) {
    let t = Je.varintBufBN(e);
    return this.write(t), this;
  }
  writeVarLengthBuf(e) {
    return R.validateArgument(W.isBuffer(e), "buf"), this.writeVarintNum(e.length), this.write(e), this;
  }
  writeCoreVarintNum(e) {
    let t = [], i = 0;
    for (; t.push(e & 127 | (i ? 128 : 0)), !(e <= 127); )
      e = (e >> 7) - 1, i++;
    return this.write(Buffer.from(t).reverse()), this;
  }
  static varintBufNum(e) {
    let t;
    return e < 253 ? (t = Buffer.alloc(1), t.writeUInt8(e, 0)) : e < 65536 ? (t = Buffer.alloc(3), t.writeUInt8(253, 0), t.writeUInt16LE(e, 1)) : e < 4294967296 ? (t = Buffer.alloc(5), t.writeUInt8(254, 0), t.writeUInt32LE(e, 1)) : (t = Buffer.alloc(9), t.writeUInt8(255, 0), t.writeInt32LE(e & -1, 1), t.writeUInt32LE(Math.floor(e / 4294967296), 5)), t;
  }
  static varintBufBN(e) {
    let t, i = e.toNumber();
    if (i < 253)
      t = Buffer.alloc(1), t.writeUInt8(i, 0);
    else if (i < 65536)
      t = Buffer.alloc(3), t.writeUInt8(253, 0), t.writeUInt16LE(i, 1);
    else if (i < 4294967296)
      t = Buffer.alloc(5), t.writeUInt8(254, 0), t.writeUInt32LE(i, 1);
    else {
      let o = new Je();
      o.writeUInt8(255), o.writeUInt64LEBN(e), t = o.concat();
    }
    return t;
  }
}
class zi {
  /**
  *  Converts `value` into a decimal string, assuming `unit` decimal
  *  places. The `unit` may be the number of decimal places or the enum of
  *  a unit (e.g. ``UnitType.MEX`` for 8 decimal places).
  *
  */
  static formatUnits(e, t) {
    let i = 2;
    return ze(t) || (R.validateArgument(qn(t) && t >= 0, "unit", "invalid unit"), i = t), Pt.divide(e, Math.pow(10, i), i);
  }
  /**
  *  Converts the decimal string `value` to a BigInt, assuming
  *  `unit` decimal places. The `unit` may the number of decimal places
  *  or the name of a unit (e.g. ``UnitType.KEX`` for 5 decimal places).
  */
  static parseUnits(e, t) {
    R.validateArgument(te(e), "value", "must be a string");
    let i = 2;
    return ze(t) || (R.validateArgument(qn(t) && t >= 0, "unit", "invalid unit"), i = t), BigInt(Pt.multiply(e, Math.pow(10, i)));
  }
  /**
  *  Converts `value` into a decimal string using 2 decimal places.
  */
  static formatNEXA(e) {
    return this.formatUnits(e, 2);
  }
  /**
  *  Converts the decimal string `NEXA` to a BigInt, using 2 decimal places.
  */
  static parseNEXA(e) {
    return this.parseUnits(e, 2);
  }
}
class Wr {
  constructor(e) {
    this.name = e.name, this.alias = e.alias, this.prefix = e.prefix, this.pubkeyhash = e.pubkeyhash, this.privatekey = e.privatekey, this.scripthash = e.scripthash, this.xpubkey = e.xpubkey, this.xprivkey = e.xprivkey, this.networkMagic = W.integerAsBuffer(e.networkMagic), this.port = e.port, this.dnsSeeds = e.dnsSeeds;
  }
  toString() {
    return this.name;
  }
}
const mi = new Wr({
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
}), To = new Wr({
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
class li {
  static {
    this._instance = new li();
  }
  get mainnet() {
    return mi;
  }
  /** @deprecated use mainnet */
  get livenet() {
    return mi;
  }
  get testnet() {
    return To;
  }
  get defaultNetwork() {
    return this._defaultNetwork;
  }
  set defaultNetwork(e) {
    this._defaultNetwork = e;
  }
  /**
  * @returns the singleton instance of NetworkManager
  */
  static getInstance() {
    return this._instance;
  }
  get(e, t) {
    if (e instanceof Wr) {
      if (this.networks.includes(e)) return e;
      if (this.networks.map((i) => i.name).includes(e.name)) return this.networks.find((i) => i.name == e.name);
    }
    return t ? this.networks.find((i) => t == "networkMagic" ? W.integerFromBuffer(i[t]) == e : i[t] == e) : this.networks.find((i) => Object.keys(i).some((o) => {
      let a = o;
      return a == "networkMagic" ? W.integerFromBuffer(i[a]) == e : i[a] == e;
    }));
  }
  create(e) {
    return new Wr(e);
  }
  add(e) {
    e instanceof Wr || (e = new Wr(e)), this.networks.push(e);
  }
  remove(e) {
    if (!(typeof e != "object" && (e = this.get(e), !e)))
      for (let t = 0; t < this.networks.length; t++) (this.networks[t] === e || JSON.stringify(this.networks[t]) == JSON.stringify(e)) && this.networks.splice(t, 1);
  }
  constructor() {
    this.networks = [
      mi,
      To
    ], this._defaultNetwork = mi;
  }
}
const Ie = li.getInstance();
class Nt {
  constructor(e) {
    this.r = e.r, this.s = e.s, this.i = e.i, this.compressed = e.compressed;
  }
  toBuffer(e = !0) {
    if (e)
      return Buffer.concat([
        this.r.toBuffer({
          size: 32
        }),
        this.s.toBuffer({
          size: 32
        })
      ]);
    let t = this.r.toBuffer(), i = this.s.toBuffer(), o = !!(t[0] & 128), a = !!(i[0] & 128), p = o ? Buffer.concat([
      Buffer.from([
        0
      ]),
      t
    ]) : t, c = a ? Buffer.concat([
      Buffer.from([
        0
      ]),
      i
    ]) : i, g = p.length, h = c.length, m = 2 + g + 2 + h;
    return Buffer.concat([
      Buffer.from([
        48,
        m,
        2,
        g
      ]),
      p,
      Buffer.from([
        2,
        h
      ]),
      c
    ]);
  }
  toTxFormat(e) {
    let t = this.toBuffer();
    return W.isBuffer(e) ? Buffer.concat([
      t,
      e
    ]) : t;
  }
  toString() {
    return this.toBuffer().toString("hex");
  }
  /**
  * Schnorr signatures are 64 bytes: r [len] 32 || s [len] 32.
  * 
  * There can be a few more bytes that is the sighashtype. It needs to be trimmed before calling this.
  */
  static fromBuffer(e, t) {
    if (e.length === 64) {
      let o = this.parseSchnorrEncodedSig(e);
      return new Nt(o);
    }
    let i = Nt.parseDER(e, t);
    return new Nt({
      r: i.r,
      s: i.s
    });
  }
  /**
  * The format used in a tx.
  * schnorr is 64 bytes, the rest are sighashtype bytes
  * 
  * @param buf 
  */
  static fromTxFormat(e) {
    let t = e.subarray(0, 64);
    return Nt.fromBuffer(t);
  }
  /**
  * This assumes the str is a raw signature and does not have sighashtype.
  * Use {@link Signature.fromTxString} when decoding a tx
  * 
  * @param str the signature hex string
  * @see fromTxString
  */
  static fromString(e) {
    let t = Buffer.from(e, "hex");
    return Nt.fromBuffer(t);
  }
  /**
  * This assumes the str might have sighashtype bytes and will trim it if needed.
  * Use this when decoding a tx signature string
  * 
  * @param str the tx signature hex string
  */
  static fromTxString(e, t = "hex") {
    return Nt.fromTxFormat(Buffer.from(e, t));
  }
  static parseSchnorrEncodedSig(e) {
    let t = e.subarray(0, 32), i = e.subarray(32, 64);
    return {
      r: X.fromBuffer(t),
      s: X.fromBuffer(i)
    };
  }
  /**
  * For ECDSA. In order to mimic the non-strict DER encoding of OpenSSL, set strict = false.
  */
  static parseDER(e, t) {
    R.validateArgument(W.isBuffer(e), "DER formatted signature should be a buffer"), oe(t) && (t = !0);
    let i = e[0];
    R.validateArgument(i === 48, "Header byte should be 0x30");
    let o = e[1], a = e.subarray(2).length;
    R.validateArgument(!t || o === a, "Length byte should length of what follows"), o = o < a ? o : a;
    let p = e[2];
    R.validateArgument(p === 2, "Integer byte for r should be 0x02");
    let c = e[3], g = e.subarray(4, 4 + c), h = X.fromBuffer(g), m = e[4] === 0;
    R.validateArgument(c === g.length, "Length of r incorrect");
    let S = e[4 + c + 0];
    R.validateArgument(S === 2, "Integer byte for s should be 0x02");
    let M = e[4 + c + 1], I = e.subarray(4 + c + 2, 4 + c + 2 + M), _ = X.fromBuffer(I), E = e[4 + c + 2 + 2] === 0;
    R.validateArgument(M === I.length, "Length of s incorrect");
    let O = 4 + c + 2 + M;
    return R.validateArgument(o === O - 2, "Length of signature incorrect"), {
      header: i,
      length: o,
      rheader: p,
      rlength: c,
      rneg: m,
      rbuf: g,
      r: h,
      sheader: S,
      slength: M,
      sneg: E,
      sbuf: I,
      s: _
    };
  }
  /**
  * ECDSA format. used for sign messages
  */
  toCompact(e, t) {
    e = typeof e == "number" ? e : this.i, t = typeof t == "boolean" ? t : this.compressed, R.validateArgument(e === 0 || e === 1 || e === 2 || e === 3, "i must be equal to 0, 1, 2, or 3");
    let i = e + 27 + 4;
    t === !1 && (i = i - 4);
    let o = Buffer.from([
      i
    ]), a = this.r.toBuffer({
      size: 32
    }), p = this.s.toBuffer({
      size: 32
    });
    return Buffer.concat([
      o,
      a,
      p
    ]);
  }
  static fromCompact(e) {
    R.validateArgument(W.isBuffer(e), "Argument is expected to be a Buffer");
    let t = !0, i = e.subarray(0, 1)[0] - 27 - 4;
    i < 0 && (t = !1, i = i + 4);
    let o = e.subarray(1, 33), a = e.subarray(33, 65);
    return R.validateArgument(i === 0 || i === 1 || i === 2 || i === 3, "i must be 0, 1, 2, or 3"), R.validateArgument(o.length === 32, "r must be 32 bytes"), R.validateArgument(a.length === 32, "s must be 32 bytes"), new Nt({
      r: X.fromBuffer(o),
      s: X.fromBuffer(a),
      i,
      compressed: t
    });
  }
}
class Es {
  constructor(e) {
    e && this.set(e);
  }
  set(e) {
    return this.hashbuf = e.hashbuf || this.hashbuf, this.endian = e.endian || this.endian, this.privkey = e.privkey || this.privkey, this.pubkey = e.pubkey || (this.privkey ? this.privkey.publicKey : this.pubkey), this.sig = e.sig || this.sig, this.verified = e.verified || this.verified, this;
  }
  sign() {
    let e = this.hashbuf, t = this.privkey, i = t.bn;
    R.validateState(!ze(e) && !ze(t) && !ze(i), "invalid parameters"), R.validateState(W.isBuffer(e) && e.length === 32, "hashbuf must be a 32 byte buffer");
    let o = X.fromBuffer(e, this.endian ? {
      endian: this.endian
    } : void 0), a = this._findSignature(i, o);
    return a.compressed = this.pubkey.compressed, this.sig = new Nt(a), this;
  }
  verify() {
    return this.verified = !this.sigError(), this;
  }
  toPublicKey() {
    return this.privkey.toPublicKey();
  }
  privkey2pubkey() {
    this.pubkey = this.privkey.toPublicKey();
  }
}
const Pc = Bc.ec;
class ye {
  static {
    this.ec = new Pc("secp256k1").curve;
  }
  static {
    this._g = new ye(this.ec.g);
  }
  constructor(e, t = !1) {
    this.ecPoint = e, t || this.validate();
  }
  /**
  * Will return the X coordinate of the Point
  *
  * @returns A BN instance of the X coordinate
  */
  getX() {
    return new X(this.ecPoint.getX().toArray());
  }
  /**
  * Will return the Y coordinate of the Point
  *
  * @returns A BN instance of the Y coordinate
  */
  getY() {
    return new X(this.ecPoint.getY().toArray());
  }
  add(e) {
    return new ye(this.ecPoint.add(e.ecPoint), !0);
  }
  mul(e) {
    let t = this.ecPoint.mul(e);
    return new ye(t, !0);
  }
  mulAdd(e, t, i) {
    let o = this.ecPoint.mulAdd(e, t.ecPoint, i);
    return new ye(o, !0);
  }
  eq(e) {
    return this.ecPoint.eq(e.ecPoint);
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
    let e;
    try {
      e = ye.ec.pointFromX(this.getX(), this.getY().isOdd());
    } catch {
      throw new Error("Point does not lie on the curve");
    }
    if (e.y.cmp(this.ecPoint.y) !== 0) throw new Error("Invalid y value for curve.");
    if (!this.ecPoint.mul(ye.getN()).isInfinity()) throw new Error("Point times N must be infinity");
    return this;
  }
  hasSquare() {
    return !this.ecPoint.isInfinity() && ye.isSquare(this.getY());
  }
  static isSquare(e) {
    let t = new X("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", "hex");
    return new X(e).toRed(X.red(t)).redPow(t.sub(X.One).div(new X(2))).fromRed().eq(new X(1));
  }
  /**
  * Instantiate a valid secp256k1 Point from the X and Y coordinates.
  *
  * @param x - The X coordinate
  * @param y - The Y coordinate
  * @see {@link https://github.com/indutny/elliptic}
  * @throws A validation error if exists
  */
  static ecPoint(e, t, i) {
    return new ye(this.ec.point(e, t, i));
  }
  /**
  *
  * Instantiate a valid secp256k1 Point from only the X coordinate
  * 
  * @param odd - If the Y coordinate is odd
  * @param x - The X coordinate
  * @throws A validation error if exists
  */
  static ecPointFromX(e, t) {
    let i;
    try {
      i = this.ec.pointFromX(t, e);
    } catch {
      throw new Error("Invalid X");
    }
    return new ye(i);
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
    return new X(this.ec.n.toArray());
  }
  static pointToCompressed(e) {
    let t = e.getX().toBuffer({
      size: 32
    }), i = e.getY().toBuffer({
      size: 32
    }), o = i[i.length - 1] % 2, a = Buffer.from(o ? [
      3
    ] : [
      2
    ]);
    return Buffer.concat([
      a,
      t
    ]);
  }
}
class Ke {
  /**
  * @param data - The pubkey data
  */
  constructor(e) {
    if (this.toObject = this.toJSON, this.toDER = this.toBuffer, R.validateArgument(!ze(e), "First argument is required, please include public key data."), e instanceof Ke)
      return e;
    if (Ke._isPublicKeyData(e))
      e.point.validate(), this.point = e.point, this.compressed = oe(e.compressed) || e.compressed, this.network = e.network || Ie.defaultNetwork;
    else throw new TypeError("First argument is an unrecognized data format.");
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
    let e = this.point.getX(), t = this.point.getY(), i = e.toBuffer({
      size: 32
    }), o = t.toBuffer({
      size: 32
    }), a;
    return this.compressed ? (o[o.length - 1] % 2 ? a = Buffer.from([
      3
    ]) : a = Buffer.from([
      2
    ]), Buffer.concat([
      a,
      i
    ])) : (a = Buffer.from([
      4
    ]), Buffer.concat([
      a,
      i,
      o
    ]));
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
  static from(e, t, i) {
    if (e instanceof Ke) return e;
    if (e instanceof ye) return this.fromPoint(e, t, i);
    if (this._isPublicKeyDto(e)) return this.fromObject(e);
    if (this._isPublicKeyData(e)) return new Ke(e);
    if (this._isPrivateKeyData(e)) return this.fromPrivateKey(e);
    if (W.isBuffer(e)) return this.fromBuffer(e, !0, i);
    if (vt.isHexa(e)) return this.fromString(e, "hex", i);
    throw new TypeError("First argument is an unrecognized data format.");
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
  static fromBuffer(e, t, i) {
    R.validateArgument(W.isBuffer(e), "Must be a hex buffer of DER encoded public key");
    let o = Ke._transformDER(e, t);
    return new Ke({
      point: o.point,
      compressed: o.compressed,
      network: i
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
  static fromPoint(e, t, i) {
    return R.validateArgument(e instanceof ye, "First argument must be an instance of Point."), new Ke({
      point: e,
      compressed: t,
      network: i
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
  static fromString(e, t, i) {
    let o = Buffer.from(e, t || "hex"), a = Ke._transformDER(o);
    return new Ke({
      point: a.point,
      compressed: a.compressed,
      network: i
    });
  }
  /**
  * Instantiate a PublicKey from PrivateKey data
  *
  * @param data - Object contains data of PrivateKey
  * @returns A new valid instance of PublicKey
  */
  static fromPrivateKey(e) {
    R.validateArgument(this._isPrivateKeyData(e), "data", "Must be data of PrivateKey");
    let t = ye.getG().mul(e.bn);
    return new Ke({
      point: t,
      compressed: e.compressed,
      network: e.network
    });
  }
  static fromJSON(e) {
    let t = Ke._transformObject(e);
    return new Ke(t);
  }
  /**
  * Check if there would be any errors when initializing a PublicKey
  *
  * @param data - The encoded data in various formats
  * @returns An error if exists
  */
  static getValidationError(e) {
    try {
      this.from(e);
    } catch (t) {
      return t;
    }
  }
  /**
  * Check if the parameters are valid
  *
  * @param data - The encoded data in various formats
  * @returns true If the public key would be valid
  */
  static isValid(e) {
    return !Ke.getValidationError(e);
  }
  static _isPublicKeyData(e) {
    return Oe(e) && "point" in e && e.point instanceof ye;
  }
  static _isPublicKeyDto(e) {
    return Oe(e) && "x" in e && "y" in e;
  }
  static _isPrivateKeyData(e) {
    return Oe(e) && "bn" in e && "network" in e;
  }
  /**
  * Internal function to transform DER into a public key point
  *
  * @param buf - An hex encoded buffer
  * @param strict - if set to false, will loosen some conditions
  * @returns An object with keys: point and compressed
  */
  static _transformDER(e, t) {
    if (R.validateArgument(W.isBuffer(e), "Must be a hex buffer of DER encoded public key"), t = oe(t) ? !0 : t, e[0] === 4 || !t && (e[0] === 6 || e[0] === 7)) {
      let i = e.subarray(1, 33), o = e.subarray(33, 65);
      if (i.length !== 32 || o.length !== 32 || e.length !== 65) throw new TypeError("Length of x and y must be 32 bytes");
      let a = new X(i), p = new X(o);
      return {
        point: ye.ecPoint(a, p),
        compressed: !1
      };
    } else if (e[0] === 3) {
      let i = e.subarray(1), o = new X(i);
      return {
        point: ye.ecPointFromX(!0, o),
        compressed: !0
      };
    } else if (e[0] === 2) {
      let i = e.subarray(1), o = new X(i);
      return {
        point: ye.ecPointFromX(!1, o),
        compressed: !0
      };
    } else throw new TypeError("Invalid DER format public key");
  }
  /**
  * Internal function to transform a JSON into a public key point
  */
  static _transformObject(e) {
    R.validateArgument(te(e.x), "x", "must be a hex string"), R.validateArgument(te(e.y), "y", "must be a hex string");
    let t = new X(e.x, "hex"), i = new X(e.y, "hex");
    return {
      point: ye.ecPoint(t, i),
      compressed: e.compressed,
      network: Ie.get(e.network)
    };
  }
}
class pr extends Es {
  set(e) {
    return this.k = e.k || this.k, super.set(e);
  }
  sigError() {
    if (!W.isBuffer(this.hashbuf) || this.hashbuf.length !== 32) return "hashbuf must be a 32 byte buffer";
    let e = this.sig.r, t = this.sig.s;
    if (!(e.gt(X.Zero) && e.lt(ye.getN())) || !(t.gt(X.Zero) && t.lt(ye.getN()))) return "r and s not in range";
    let i = X.fromBuffer(this.hashbuf, this.endian ? {
      endian: this.endian
    } : void 0), o = ye.getN(), a = t.invm(o), p = a.mul(i).umod(o), c = a.mul(e).umod(o), g = ye.getG().mulAdd(new X(p), this.pubkey.point, new X(c));
    return g.ecPoint.isInfinity() ? "p is infinity" : g.getX().umod(o).cmp(e) !== 0 ? "Invalid signature" : !1;
  }
  _findSignature(e, t) {
    let i = ye.getN(), o = ye.getG(), a = 0, p, c, g, h;
    do
      (!this.k || a > 0) && this.deterministicK(a), a++, p = this.k, c = o.mul(p), g = c.ecPoint.x.umod(i), h = p.invm(i).mul(t.add(e.mul(g))).umod(i);
    while (g.cmp(X.Zero) <= 0 || h.cmp(X.Zero) <= 0);
    return h = pr.toLowS(new X(h)), {
      s: h,
      r: new X(g)
    };
  }
  static toLowS(e) {
    return e.gt(X.fromBuffer(Buffer.from("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", "hex"))) && (e = ye.getN().sub(e)), e;
  }
  calcI() {
    for (let e = 0; e < 4; e++) {
      this.sig.i = e;
      let t;
      try {
        t = this.toPublicKey();
      } catch {
        continue;
      }
      if (t.point.eq(this.pubkey.point))
        return this.sig.compressed = this.pubkey.compressed, this;
    }
    throw this.sig.i = void 0, new Error("Unable to find valid recovery factor");
  }
  randomK() {
    let e = ye.getN(), t;
    do
      t = X.fromBuffer(W.getRandomBuffer(32));
    while (!(t.lt(e) && t.gt(X.Zero)));
    return this.k = t, this;
  }
  // https://tools.ietf.org/html/rfc6979#section-3.2
  deterministicK(e) {
    oe(e) && (e = 0);
    let t = Buffer.alloc(32);
    t.fill(1);
    let i = Buffer.alloc(32);
    i.fill(0);
    let o = this.privkey.bn.toBuffer({
      size: 32
    }), a = this.endian === "little" ? W.reverse(this.hashbuf) : this.hashbuf;
    i = le.sha256hmac(Buffer.concat([
      t,
      Buffer.from([
        0
      ]),
      o,
      a
    ]), i), t = le.sha256hmac(t, i), i = le.sha256hmac(Buffer.concat([
      t,
      Buffer.from([
        1
      ]),
      o,
      a
    ]), i), t = le.sha256hmac(t, i), t = le.sha256hmac(t, i);
    let p = X.fromBuffer(t), c = ye.getN();
    for (let g = 0; g < e || !(p.lt(c) && p.gt(X.Zero)); g++)
      i = le.sha256hmac(Buffer.concat([
        t,
        Buffer.from([
          0
        ])
      ]), i), t = le.sha256hmac(t, i), t = le.sha256hmac(t, i), p = X.fromBuffer(t);
    return this.k = p, this;
  }
  signRandomK() {
    return this.randomK(), this.sign();
  }
  toString() {
    let e = {};
    return this.hashbuf && (e.hashbuf = this.hashbuf.toString("hex")), this.privkey && (e.privkey = this.privkey.toString()), this.pubkey && (e.pubkey = this.pubkey.toString()), this.sig && (e.sig = this.sig.toString()), this.k && (e.k = this.k.toString()), JSON.stringify(e);
  }
  // Information about public key recovery:
  // https://bitcointalk.org/index.php?topic=6430.0
  // http://stackoverflow.com/questions/19665491/how-do-i-get-an-ecdsa-public-key-from-just-a-bitcoin-signature-sec1-4-1-6-k
  toPublicKey() {
    let e = this.sig.i;
    R.validateArgument(e === 0 || e === 1 || e === 2 || e === 3, "i must be equal to 0, 1, 2, or 3");
    let t = X.fromBuffer(this.hashbuf), i = this.sig.r, o = this.sig.s, a = e & 1, p = e >> 1, c = ye.getN(), g = ye.getG(), h = p ? i.add(c) : i, m = ye.ecPointFromX(!!a, h);
    if (!m.mul(c).ecPoint.isInfinity()) throw new Error("nR is not a valid curve point");
    let M = t.neg().umod(c), I = i.invm(c), _ = m.mul(o).add(g.mul(new X(M))).mul(new X(I));
    return Ke.fromPoint(_, this.sig.compressed);
  }
  static fromString(e) {
    let t = JSON.parse(e);
    return new pr(t);
  }
  static sign(e, t, i) {
    return new pr({
      hashbuf: e,
      endian: i,
      privkey: t
    }).sign().sig;
  }
  static verify(e, t, i, o) {
    return new pr({
      hashbuf: e,
      endian: o,
      sig: t,
      pubkey: i
    }).verify().verified;
  }
}
class $t extends Es {
  sigError() {
    if (!W.isBuffer(this.hashbuf) || this.hashbuf.length !== 32) return "hashbuf must be a 32 byte buffer";
    let e = $t.getProperSizeBuffer(this.sig.r).length + $t.getProperSizeBuffer(this.sig.s).length;
    if (!(e === 64 || e === 65)) return "signature must be a 64 byte or 65 byte array";
    let t = this.endian === "little" ? W.reverse(this.hashbuf) : this.hashbuf, i = this.pubkey.point, o = ye.getG();
    if (i.ecPoint.isInfinity()) return !0;
    let a = this.sig.r, p = this.sig.s, c = new X("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", "hex"), g = ye.getN();
    if (a.gte(c) || p.gte(g))
      return !0;
    let h = $t.getProperSizeBuffer(this.sig.r), m = ye.pointToCompressed(i), S = le.sha256(Buffer.concat([
      h,
      m,
      t
    ])), M = X.fromBuffer(S, {
      endian: "big"
    }).umod(g), I = o.mul(p), _ = i.mul(g.sub(M)), E = I.add(_);
    return !!(E.ecPoint.isInfinity() || !E.hasSquare() || !E.getX().eq(a));
  }
  /**
  * RFC6979 deterministic nonce generation used from https://reviews.bitcoinabc.org/D2501
  * 
  * @param privkeybuf 
  * @param msgbuf 
  * @return BN nonce
  */
  nonceFunctionRFC6979(e, t) {
    let i = Buffer.from("0101010101010101010101010101010101010101010101010101010101010101", "hex"), o = Buffer.from("0000000000000000000000000000000000000000000000000000000000000000", "hex"), a = Buffer.concat([
      e,
      t,
      Buffer.from("", "ascii"),
      Buffer.from("Schnorr+SHA256  ", "ascii")
    ]);
    o = le.sha256hmac(Buffer.concat([
      i,
      Buffer.from("00", "hex"),
      a
    ]), o), i = le.sha256hmac(i, o), o = le.sha256hmac(Buffer.concat([
      i,
      Buffer.from("01", "hex"),
      a
    ]), o), i = le.sha256hmac(i, o);
    let p = new X(0), c;
    for (; i = le.sha256hmac(i, o), c = X.fromBuffer(i), p = c, R.validateState(i.length >= 32, "V length should be >= 32"), !(p.gt(new X(0)) && p.lt(ye.getN())); )
      o = le.sha256hmac(Buffer.concat([
        i,
        Buffer.from("00", "hex")
      ]), o), i = le.sha256hmac(i, o);
    return p;
  }
  /**
  * @remarks
  * Important references for schnorr implementation {@link https://spec.nexa.org/forks/2019-05-15-schnorr/}
  * 
  * @param d the private key
  * @param e the message to be signed
  */
  _findSignature(e, t) {
    let i = ye.getN(), o = ye.getG();
    R.validateState(!e.lte(new X(0)), "privkey out of field of curve"), R.validateState(!e.gte(i), "privkey out of field of curve");
    let a = this.nonceFunctionRFC6979(e.toBuffer({
      size: 32
    }), t.toBuffer({
      size: 32
    })), p = o.mul(e), c = o.mul(a);
    c.hasSquare() || (a = i.sub(a));
    let g = c.getX(), m = X.fromBuffer(le.sha256(Buffer.concat([
      $t.getProperSizeBuffer(g),
      ye.pointToCompressed(p),
      t.toBuffer({
        size: 32
      })
    ]))).mul(e).add(a).mod(i);
    return {
      r: g,
      s: m
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
  static getProperSizeBuffer(e) {
    return e.toBuffer().length < 32 ? e.toBuffer({
      size: 32
    }) : e.toBuffer();
  }
  static sign(e, t, i) {
    return new $t({
      hashbuf: e,
      endian: i,
      privkey: t
    }).sign().sig;
  }
  static verify(e, t, i, o) {
    return new $t({
      hashbuf: e,
      endian: o,
      sig: t,
      pubkey: i
    }).verify().verified;
  }
}
class er {
  static {
    this.ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".split("");
  }
  constructor(e) {
    if (Buffer.isBuffer(e)) {
      let t = e;
      this.fromBuffer(t);
    } else if (typeof e == "string") {
      let t = e;
      this.fromString(t);
    } else e && this.set(e);
  }
  toBuffer() {
    return this.buf;
  }
  toString() {
    return this.buf ? er.encode(this.buf) : "";
  }
  fromBuffer(e) {
    return this.buf = e, this;
  }
  fromString(e) {
    let t = er.decode(e);
    return this.buf = t, this;
  }
  set(e) {
    return this.buf = e.buf || this.buf || void 0, this;
  }
  static encode(e) {
    if (!Buffer.isBuffer(e)) throw new Error("Input should be a buffer");
    return Po.encode(e);
  }
  static decode(e) {
    if (typeof e != "string") throw new Error("Input should be a string");
    return Buffer.from(Po.decode(e));
  }
  static validCharacters(e) {
    return Buffer.isBuffer(e) && (e = e.toString()), e.split("").every((t) => er.ALPHABET.includes(t));
  }
}
class Ct {
  constructor(e) {
    if (Buffer.isBuffer(e)) {
      let t = e;
      this.fromBuffer(t);
    } else if (typeof e == "string") {
      let t = e;
      this.fromString(t);
    } else e && this.set(e);
  }
  static validChecksum(e, t) {
    return te(e) && (e = Buffer.from(er.decode(e))), te(t) && (t = Buffer.from(er.decode(t))), t || (t = e.subarray(-4), e = e.subarray(0, -4)), Ct.checksum(e).toString("hex") === t.toString("hex");
  }
  static decode(e) {
    if (typeof e != "string") throw new Error("Input must be a string");
    let t = Buffer.from(er.decode(e));
    if (t.length < 4) throw new Error("Input string too short");
    let i = t.subarray(0, -4), o = t.subarray(-4), p = le.sha256sha256(i).subarray(0, 4);
    if (o.toString("hex") !== p.toString("hex")) throw new Error("Checksum mismatch");
    return i;
  }
  static checksum(e) {
    return le.sha256sha256(e).subarray(0, 4);
  }
  static encode(e) {
    if (!Buffer.isBuffer(e)) throw new Error("Input must be a buffer");
    let t = Buffer.alloc(e.length + 4), i = Ct.checksum(e);
    return e.copy(t), i.copy(t, e.length), er.encode(t);
  }
  toBuffer() {
    return this.buf;
  }
  toString() {
    return this.buf ? Ct.encode(this.buf) : "";
  }
  fromBuffer(e) {
    return this.buf = e, this;
  }
  fromString(e) {
    let t = Ct.decode(e);
    return this.buf = t, this;
  }
  set(e) {
    return this.buf = e.buf || this.buf || void 0, this;
  }
}
class zo {
  static {
    this.CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  }
  static {
    this.CHARSET_INVERSE_INDEX = {
      q: 0,
      p: 1,
      z: 2,
      r: 3,
      y: 4,
      9: 5,
      x: 6,
      8: 7,
      g: 8,
      f: 9,
      2: 10,
      t: 11,
      v: 12,
      d: 13,
      w: 14,
      0: 15,
      s: 16,
      3: 17,
      j: 18,
      n: 19,
      5: 20,
      4: 21,
      k: 22,
      h: 23,
      c: 24,
      e: 25,
      6: 26,
      m: 27,
      u: 28,
      a: 29,
      7: 30,
      l: 31
    };
  }
  /***
  * Encodes the given array of 5-bit integers as a base32-encoded string.
  *
  * @param data Array of integers between 0 and 31 inclusive.
  */
  static encode(e) {
    R.validateArgument(e instanceof Array, "Must be Array");
    let t = "";
    return e.forEach((i) => {
      R.validateArgument(0 <= i && i < 32, "value " + i), t += this.CHARSET[i];
    }), t;
  }
  /***
  * Decodes the given base32-encoded string into an array of 5-bit integers.
  *
  * @param base32 
  */
  static decode(e) {
    R.validateArgument(typeof e == "string", "Must be base32-encoded string");
    let t = [];
    for (let i of e)
      R.validateArgument(i in this.CHARSET_INVERSE_INDEX, "value " + i), t.push(this.CHARSET_INVERSE_INDEX[i]);
    return t;
  }
}
var Ye = /* @__PURE__ */ (function(r) {
  return r.PayToPublicKeyHash = "P2PKH", r.PayToScriptTemplate = "P2ST", r.GroupIdAddress = "GROUP", r;
})({});
class ka {
  static {
    this.VALID_PREFIXES = [
      "nexa",
      "nexatest"
    ];
  }
  /** @see encodeAddress */
  static encode(e, t, i) {
    return this.encodeAddress({
      prefix: e,
      type: t,
      data: i
    });
  }
  /**
  * Encodes a hash from a given type into a Nexa address with the given prefix.
  *
  * @param address Object contains Network prefix (E.g.: 'nexa'), Type of address to generate and data to encode.
  */
  static encodeAddress(e) {
    R.validateArgument(typeof e.prefix == "string" && this.isValidPrefix(e.prefix), "Invalid prefix: " + e.prefix + "."), R.validateArgument(typeof e.type == "string", "Invalid type: " + e.type + "."), R.validateArgument(W.isBuffer(e.data), "Invalid data: " + e.data + ".");
    let t = [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ], i = this.prefixToArray(e.prefix).concat([
      0
    ]), o = this.getTypeBits(e.type), a = this.convertBits(Buffer.concat([
      Buffer.from([
        o
      ]),
      e.data
    ]), 8, 5), p = i.concat(a).concat(t), c = a.concat(this.checksumToArray(this.polymod(p)));
    return e.prefix + ":" + zo.encode(c);
  }
  /**
  * Decodes the given address into its constituting prefix, type and data. See {@link encodeAddress}.
  *
  * @param {string} address Address to decode. E.g.: 'nexa:qpm2qsznhks23z7629mms6s4cwef74vcwvgpsey0xy'.
  */
  static decode(e) {
    R.validateArgument(typeof e == "string" && this.hasSingleCase(e), "Invalid address: " + e + ".");
    let t = e.toLowerCase().split(":");
    R.validateState(t.length === 2, "Missing prefix: " + e + ".");
    let i = t[0], o = zo.decode(t[1]);
    R.validateState(this.validChecksum(i, o), "Invalid checksum: " + e + ".");
    let a = this.convertBits(o.slice(0, -8), 5, 8, !0), p = a.shift(), c = a, g = this.getType(p);
    return {
      prefix: i,
      type: g,
      data: Buffer.from(c)
    };
  }
  /**
  * Checks whether a string is a valid prefix; ie., it has a single letter case
  * and is one of the above.
  * 
  * @param prefix
  */
  static isValidPrefix(e) {
    return this.hasSingleCase(e) && this.VALID_PREFIXES.includes(e.toLowerCase());
  }
  /**
  * Derives an array from the given prefix to be used in the computation
  * of the address' checksum.
  *
  * @param prefix Network prefix. E.g.: 'nexa'.
  */
  static prefixToArray(e) {
    let t = [];
    for (let i = 0; i < e.length; ++i) t.push(e.charCodeAt(i) & 31);
    return t;
  }
  /**
  * Returns an array representation of the given checksum to be encoded
  * within the address' payload.
  *
  * @param checksum Computed checksum.
  */
  static checksumToArray(e) {
    let t = [];
    for (let i = 0; i < 8; ++i)
      t.push(e & 31), e /= 32;
    return t.reverse();
  }
  /**
  * Returns the bit representation of the given type within the version byte.
  *
  * @param type Address type. Either 'P2PKH' or 'P2SH'.
  */
  static getTypeBits(e) {
    switch (e) {
      case "P2PKH":
        return 0;
      case "P2ST":
        return 152;
      case "GROUP":
        return 88;
      default:
        throw new TypeError("Invalid type: " + e + ".");
    }
  }
  /**
  * Retrieves the address type from its bit representation within the
  * version byte.
  *
  * @param versionByte
  */
  static getType(e) {
    switch (e & 248) {
      case 0:
        return "P2PKH";
      case 152:
        return "P2ST";
      case 88:
        return "GROUP";
      default:
        throw new Error("Invalid address type in version byte: " + e + ".");
    }
  }
  /**
  * Returns true if, and only if, the given string contains either uppercase
  * or lowercase letters, but not both.
  *
  * @param string Input string.
  */
  static hasSingleCase(e) {
    return e === e.toLowerCase() || e === e.toUpperCase();
  }
  /**
  * Verify that the payload has not been corrupted by checking that the
  * checksum is valid.
  *
  * @param prefix Network prefix. E.g.: 'nexa'.
  * @param payload Array of 5-bit integers containing the address' payload.
  */
  static validChecksum(e, t) {
    let i = this.prefixToArray(e).concat([
      0
    ]);
    return this.polymod(i.concat(t)) === 0;
  }
  /**
  * Computes a checksum from the given input data as specified for the CashAddr
  * format: https://github.com/Bitcoin-UAHF/spec/blob/master/cashaddr.md.
  *
  * @param data Array of 5-bit integers over which the checksum is to be computed.
  */
  static polymod(e) {
    let t = [
      152,
      121,
      243,
      174,
      30
    ], i = [
      4072443489,
      3077413346,
      1046459332,
      783016616,
      1329849456
    ], o = 0, a = 1, p = 0;
    for (let c = 0; c < e.length; c++) {
      p = o >>> 3, o &= 7, o <<= 5, o |= a >>> 27, a &= 134217727, a <<= 5, a ^= e[c];
      for (let g = 0; g < t.length; ++g) p & 1 << g && (o ^= t[g], a ^= i[g]);
    }
    return a ^= 1, a < 0 && (a ^= -2147483648, a += 1073741824 * 2), o * 1073741824 * 4 + a;
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
  static convertBits(e, t, i, o = !1) {
    let a = 0, p = 0, c = [], g = (1 << i) - 1;
    for (let h = 0; h < e.length; h++) {
      let m = e[h];
      for (R.validateArgument(!(m < 0 || m >> t !== 0), "value " + m), a = a << t | m, p += t; p >= i; )
        p -= i, c.push(a >> p & g);
    }
    return o ? R.validateState(!(p >= t || a << i - p & g), "Conversion requires padding but strict mode was used") : p > 0 && c.push(a << i - p & g), c;
  }
}
var $ = /* @__PURE__ */ (function(r) {
  return r[r.OP_FALSE = 0] = "OP_FALSE", r[r.OP_0 = 0] = "OP_0", r[r.OP_PUSHDATA1 = 76] = "OP_PUSHDATA1", r[r.OP_PUSHDATA2 = 77] = "OP_PUSHDATA2", r[r.OP_PUSHDATA4 = 78] = "OP_PUSHDATA4", r[r.OP_1NEGATE = 79] = "OP_1NEGATE", r[r.OP_RESERVED = 80] = "OP_RESERVED", r[r.OP_TRUE = 81] = "OP_TRUE", r[r.OP_1 = 81] = "OP_1", r[r.OP_2 = 82] = "OP_2", r[r.OP_3 = 83] = "OP_3", r[r.OP_4 = 84] = "OP_4", r[r.OP_5 = 85] = "OP_5", r[r.OP_6 = 86] = "OP_6", r[r.OP_7 = 87] = "OP_7", r[r.OP_8 = 88] = "OP_8", r[r.OP_9 = 89] = "OP_9", r[r.OP_10 = 90] = "OP_10", r[r.OP_11 = 91] = "OP_11", r[r.OP_12 = 92] = "OP_12", r[r.OP_13 = 93] = "OP_13", r[r.OP_14 = 94] = "OP_14", r[r.OP_15 = 95] = "OP_15", r[r.OP_16 = 96] = "OP_16", r[r.OP_NOP = 97] = "OP_NOP", r[r.OP_INVALID_CONTROL1 = 98] = "OP_INVALID_CONTROL1", r[r.OP_IF = 99] = "OP_IF", r[r.OP_NOTIF = 100] = "OP_NOTIF", r[r.OP_JUMP = 101] = "OP_JUMP", r[r.OP_INVALID_CONTROL2 = 102] = "OP_INVALID_CONTROL2", r[r.OP_ELSE = 103] = "OP_ELSE", r[r.OP_ENDIF = 104] = "OP_ENDIF", r[r.OP_VERIFY = 105] = "OP_VERIFY", r[r.OP_RETURN = 106] = "OP_RETURN", r[r.OP_TOALTSTACK = 107] = "OP_TOALTSTACK", r[r.OP_FROMALTSTACK = 108] = "OP_FROMALTSTACK", r[r.OP_2DROP = 109] = "OP_2DROP", r[r.OP_2DUP = 110] = "OP_2DUP", r[r.OP_3DUP = 111] = "OP_3DUP", r[r.OP_2OVER = 112] = "OP_2OVER", r[r.OP_2ROT = 113] = "OP_2ROT", r[r.OP_2SWAP = 114] = "OP_2SWAP", r[r.OP_IFDUP = 115] = "OP_IFDUP", r[r.OP_DEPTH = 116] = "OP_DEPTH", r[r.OP_DROP = 117] = "OP_DROP", r[r.OP_DUP = 118] = "OP_DUP", r[r.OP_NIP = 119] = "OP_NIP", r[r.OP_OVER = 120] = "OP_OVER", r[r.OP_PICK = 121] = "OP_PICK", r[r.OP_ROLL = 122] = "OP_ROLL", r[r.OP_ROT = 123] = "OP_ROT", r[r.OP_SWAP = 124] = "OP_SWAP", r[r.OP_TUCK = 125] = "OP_TUCK", r[r.OP_CAT = 126] = "OP_CAT", r[r.OP_SPLIT = 127] = "OP_SPLIT", r[r.OP_NUM2BIN = 128] = "OP_NUM2BIN", r[r.OP_BIN2NUM = 129] = "OP_BIN2NUM", r[r.OP_SIZE = 130] = "OP_SIZE", r[r.OP_INVERT = 131] = "OP_INVERT", r[r.OP_AND = 132] = "OP_AND", r[r.OP_OR = 133] = "OP_OR", r[r.OP_XOR = 134] = "OP_XOR", r[r.OP_EQUAL = 135] = "OP_EQUAL", r[r.OP_EQUALVERIFY = 136] = "OP_EQUALVERIFY", r[r.OP_RESERVED1 = 137] = "OP_RESERVED1", r[r.OP_RESERVED2 = 138] = "OP_RESERVED2", r[r.OP_1ADD = 139] = "OP_1ADD", r[r.OP_1SUB = 140] = "OP_1SUB", r[r.OP_2MUL = 141] = "OP_2MUL", r[r.OP_2DIV = 142] = "OP_2DIV", r[r.OP_NEGATE = 143] = "OP_NEGATE", r[r.OP_ABS = 144] = "OP_ABS", r[r.OP_NOT = 145] = "OP_NOT", r[r.OP_0NOTEQUAL = 146] = "OP_0NOTEQUAL", r[r.OP_ADD = 147] = "OP_ADD", r[r.OP_SUB = 148] = "OP_SUB", r[r.OP_MUL = 149] = "OP_MUL", r[r.OP_DIV = 150] = "OP_DIV", r[r.OP_MOD = 151] = "OP_MOD", r[r.OP_LSHIFT = 152] = "OP_LSHIFT", r[r.OP_RSHIFT = 153] = "OP_RSHIFT", r[r.OP_BOOLAND = 154] = "OP_BOOLAND", r[r.OP_BOOLOR = 155] = "OP_BOOLOR", r[r.OP_NUMEQUAL = 156] = "OP_NUMEQUAL", r[r.OP_NUMEQUALVERIFY = 157] = "OP_NUMEQUALVERIFY", r[r.OP_NUMNOTEQUAL = 158] = "OP_NUMNOTEQUAL", r[r.OP_LESSTHAN = 159] = "OP_LESSTHAN", r[r.OP_GREATERTHAN = 160] = "OP_GREATERTHAN", r[r.OP_LESSTHANOREQUAL = 161] = "OP_LESSTHANOREQUAL", r[r.OP_GREATERTHANOREQUAL = 162] = "OP_GREATERTHANOREQUAL", r[r.OP_MIN = 163] = "OP_MIN", r[r.OP_MAX = 164] = "OP_MAX", r[r.OP_WITHIN = 165] = "OP_WITHIN", r[r.OP_RIPEMD160 = 166] = "OP_RIPEMD160", r[r.OP_SHA1 = 167] = "OP_SHA1", r[r.OP_SHA256 = 168] = "OP_SHA256", r[r.OP_HASH160 = 169] = "OP_HASH160", r[r.OP_HASH256 = 170] = "OP_HASH256", r[r.OP_CODESEPARATOR = 171] = "OP_CODESEPARATOR", r[r.OP_CHECKSIG = 172] = "OP_CHECKSIG", r[r.OP_CHECKSIGVERIFY = 173] = "OP_CHECKSIGVERIFY", r[r.OP_CHECKMULTISIG = 174] = "OP_CHECKMULTISIG", r[r.OP_CHECKMULTISIGVERIFY = 175] = "OP_CHECKMULTISIGVERIFY", r[r.OP_NOP2 = 177] = "OP_NOP2", r[r.OP_CHECKLOCKTIMEVERIFY = 177] = "OP_CHECKLOCKTIMEVERIFY", r[r.OP_NOP3 = 178] = "OP_NOP3", r[r.OP_CHECKSEQUENCEVERIFY = 178] = "OP_CHECKSEQUENCEVERIFY", r[r.OP_NOP1 = 176] = "OP_NOP1", r[r.OP_NOP4 = 179] = "OP_NOP4", r[r.OP_NOP5 = 180] = "OP_NOP5", r[r.OP_NOP6 = 181] = "OP_NOP6", r[r.OP_NOP7 = 182] = "OP_NOP7", r[r.OP_NOP8 = 183] = "OP_NOP8", r[r.OP_NOP9 = 184] = "OP_NOP9", r[r.OP_NOP10 = 185] = "OP_NOP10", r[r.OP_CHECKDATASIG = 186] = "OP_CHECKDATASIG", r[r.OP_CHECKDATASIGVERIFY = 187] = "OP_CHECKDATASIGVERIFY", r[r.OP_REVERSEBYTES = 188] = "OP_REVERSEBYTES", r[r.OP_INPUTINDEX = 192] = "OP_INPUTINDEX", r[r.OP_ACTIVEBYTECODE = 193] = "OP_ACTIVEBYTECODE", r[r.OP_TXVERSION = 194] = "OP_TXVERSION", r[r.OP_TXINPUTCOUNT = 195] = "OP_TXINPUTCOUNT", r[r.OP_TXOUTPUTCOUNT = 196] = "OP_TXOUTPUTCOUNT", r[r.OP_TXLOCKTIME = 197] = "OP_TXLOCKTIME", r[r.OP_UTXOVALUE = 198] = "OP_UTXOVALUE", r[r.OP_UTXOBYTECODE = 199] = "OP_UTXOBYTECODE", r[r.OP_OUTPOINTHASH = 200] = "OP_OUTPOINTHASH", r[r.OP_INPUTBYTECODE = 202] = "OP_INPUTBYTECODE", r[r.OP_INPUTSEQUENCENUMBER = 203] = "OP_INPUTSEQUENCENUMBER", r[r.OP_OUTPUTVALUE = 204] = "OP_OUTPUTVALUE", r[r.OP_OUTPUTBYTECODE = 205] = "OP_OUTPUTBYTECODE", r[r.OP_INPUTTYPE = 206] = "OP_INPUTTYPE", r[r.OP_OUTPUTTYPE = 207] = "OP_OUTPUTTYPE", r[r.OP_INPUTVALUE = 208] = "OP_INPUTVALUE", r[r.OP_PARSE = 230] = "OP_PARSE", r[r.OP_STORE = 231] = "OP_STORE", r[r.OP_LOAD = 232] = "OP_LOAD", r[r.OP_PLACE = 233] = "OP_PLACE", r[r.OP_PUSH_TX_STATE = 234] = "OP_PUSH_TX_STATE", r[r.OP_SETBMD = 235] = "OP_SETBMD", r[r.OP_BIN2BIGNUM = 236] = "OP_BIN2BIGNUM", r[r.OP_EXEC = 237] = "OP_EXEC", r[r.OP_MERKLEROOT = 238] = "OP_MERKLEROOT", r[r.FIRST_UNDEFINED_OP_VALUE = 239] = "FIRST_UNDEFINED_OP_VALUE", r[r.OP_INVALIDOPCODE = 255] = "OP_INVALIDOPCODE", r;
})({});
class mt {
  constructor(e) {
    if (Tt(e)) this.num = e;
    else if (te(e)) this.num = $[e];
    else throw new TypeError('Unrecognized val type: "' + typeof e + '" for Opcode');
  }
  static fromBuffer(e) {
    return R.validateArgument(W.isBuffer(e), "buf must be Buffer"), new mt(+("0x" + e.toString("hex")));
  }
  static fromNumber(e) {
    return R.validateArgument(Tt(e), "num must be number"), new mt(e);
  }
  static fromString(e) {
    R.validateArgument(te(e), "str must be string");
    let t = $[e];
    if (typeof t > "u") throw new TypeError("Invalid opcodestr");
    return new mt(t);
  }
  static smallInt(e) {
    return R.validateArgument(Tt(e), "n should be number"), R.validateArgument(e >= 0 && e <= 16, "n must be between 0 and 16"), e === 0 ? new mt("OP_0") : new mt(81 + e - 1);
  }
  /**
  * @returns true if opcode is one of OP_0, OP_1, ..., OP_16
  */
  static isSmallIntOp(e) {
    return e instanceof mt && (e = e.toNumber()), e === 0 || e >= 81 && e <= 96;
  }
  toHex() {
    return this.num.toString(16);
  }
  toBuffer() {
    return Buffer.from(this.toHex(), "hex");
  }
  toNumber() {
    return this.num;
  }
  toString() {
    let e = $[this.num];
    if (typeof e > "u") throw new Error("Opcode does not have a string representation");
    return e;
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
  static decodeOP_N(e) {
    if (e === 0) return 0;
    if (e >= 81 && e <= 96) return e - 80;
    throw new Error("Invalid opcode: " + JSON.stringify(e));
  }
}
class ee {
  constructor(e) {
    if (this.append = this.add, this.chunks = [], !!e) {
      if (W.isBuffer(e)) return ee.fromBuffer(e);
      if (e instanceof ee) return ee.fromBuffer(e.toBuffer());
      if (te(e)) return ee.fromString(e);
      ee._isScriptObject(e) && this.set(e);
    }
  }
  static _isScriptObject(e) {
    return Oe(e) && "chunks" in e && rr(e.chunks);
  }
  static _isScriptChunk(e) {
    return Oe(e) && "opcodenum" in e;
  }
  set(e) {
    return R.validateArgument(ee._isScriptObject(e), "obj"), this.chunks = e.chunks, this;
  }
  /**
  * @returns a new empty script
  */
  static empty() {
    return new ee();
  }
  static fromBuffer(e) {
    let t = new ee();
    t.chunks = [];
    let i = new Ui(e);
    for (; !i.finished(); ) try {
      let o = i.readUInt8(), a, p;
      o > 0 && o < $.OP_PUSHDATA1 ? (a = o, t.chunks.push({
        buf: i.read(a),
        len: a,
        opcodenum: o
      })) : o === $.OP_PUSHDATA1 ? (a = i.readUInt8(), p = i.read(a), t.chunks.push({
        buf: p,
        len: a,
        opcodenum: o
      })) : o === $.OP_PUSHDATA2 ? (a = i.readUInt16LE(), p = i.read(a), t.chunks.push({
        buf: p,
        len: a,
        opcodenum: o
      })) : o === $.OP_PUSHDATA4 ? (a = i.readUInt32LE(), p = i.read(a), t.chunks.push({
        buf: p,
        len: a,
        opcodenum: o
      })) : t.chunks.push({
        opcodenum: o
      });
    } catch (o) {
      throw o instanceof RangeError ? new Error(`Invalid script buffer: can't parse valid script from given buffer ${e.toString("hex")}`) : o;
    }
    return t;
  }
  toBuffer() {
    let e = new Je();
    return this.chunks.forEach((t) => {
      e.writeUInt8(t.opcodenum), t.buf && (t.opcodenum < $.OP_PUSHDATA1 ? e.write(t.buf) : t.opcodenum === $.OP_PUSHDATA1 ? (e.writeUInt8(t.len), e.write(t.buf)) : t.opcodenum === $.OP_PUSHDATA2 ? (e.writeUInt16LE(t.len), e.write(t.buf)) : t.opcodenum === $.OP_PUSHDATA4 && (e.writeUInt32LE(t.len), e.write(t.buf)));
    }), e.concat();
  }
  static fromHex(e) {
    return new ee(Buffer.from(e, "hex"));
  }
  static fromString(e) {
    if (vt.isHexa(e) || e.length === 0) return this.fromHex(e);
    let t = new ee();
    t.chunks = [];
    let i = e.split(" "), o = 0;
    for (; o < i.length; ) {
      let a = i[o], c = new mt(a).toNumber();
      if (oe(c))
        if (c = parseInt(a), c > 0 && c < $.OP_PUSHDATA1)
          t.chunks.push({
            buf: Buffer.from(i[o + 1].slice(2), "hex"),
            len: c,
            opcodenum: c
          }), o = o + 2;
        else throw new Error("Invalid script: " + JSON.stringify(e));
      else if (c === $.OP_PUSHDATA1 || c === $.OP_PUSHDATA2 || c === $.OP_PUSHDATA4) {
        if (i[o + 2].slice(0, 2) !== "0x") throw new Error("Pushdata data must start with 0x");
        t.chunks.push({
          buf: Buffer.from(i[o + 2].slice(2), "hex"),
          len: parseInt(i[o + 1]),
          opcodenum: c
        }), o = o + 3;
      } else
        t.chunks.push({
          opcodenum: c
        }), o = o + 1;
    }
    return t;
  }
  static fromASM(e) {
    let t = new ee();
    t.chunks = [];
    let i = e.split(" "), o = 0;
    for (; o < i.length; ) {
      let a = i[o], c = new mt(a).toNumber();
      if (oe(c)) {
        let g = Buffer.from(i[o], "hex"), h = g.length;
        h >= 0 && h < $.OP_PUSHDATA1 ? c = h : h < Math.pow(2, 8) ? c = $.OP_PUSHDATA1 : h < Math.pow(2, 16) ? c = $.OP_PUSHDATA2 : h < Math.pow(2, 32) && (c = $.OP_PUSHDATA4), t.chunks.push({
          buf: g,
          len: g.length,
          opcodenum: c
        }), o = o + 1;
      } else
        t.chunks.push({
          opcodenum: c
        }), o = o + 1;
    }
    return t;
  }
  static _chunkToString(e, t = !1) {
    let i = e.opcodenum, o = "";
    if (e.buf)
      !t && (i === $.OP_PUSHDATA1 || i === $.OP_PUSHDATA2 || i === $.OP_PUSHDATA4) && (o = o + " " + new mt(i).toString()), e.len > 0 && (t ? o = o + " " + e.buf.toString("hex") : o = o + " " + e.len + " 0x" + e.buf.toString("hex"));
    else if (typeof $[i] < "u")
      t ? i === 0 ? o = o + " 0" : i === 79 ? o = o + " -1" : o = o + " " + new mt(i).toString() : o = o + " " + new mt(i).toString();
    else {
      let a = i.toString(16);
      a.length % 2 !== 0 && (a = "0" + a), t ? o = o + " " + a : o = o + " 0x" + a;
    }
    return o;
  }
  toASM() {
    return this.chunks.map((e) => ee._chunkToString(e, !0)).join("").substring(1);
  }
  toString() {
    return this.chunks.map((e) => ee._chunkToString(e)).join("").substring(1);
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
  add(e) {
    return this._addByType(e, !1), this;
  }
  /**
  * Adds a script element at the start of the script.
  * @param param a script element to add
  * @returns this script instance
  */
  prepend(e) {
    return this._addByType(e, !0), this;
  }
  _addByType(e, t) {
    if (typeof e == "string") this._addOpcode(e, t);
    else if (typeof e == "number") this._addOpcode(e, t);
    else if (e instanceof mt) this._addOpcode(e, t);
    else if (typeof e == "bigint")
      e <= 16n ? this._addOpcode(mt.smallInt(Number(e)), t) : e === 0x81n ? this._addOpcode($.OP_1NEGATE, t) : this._addBuffer(new X(e.toString()).toScriptNumBuffer(), t);
    else if (typeof e == "boolean") this._addOpcode(e ? $.OP_TRUE : $.OP_FALSE, t);
    else if (W.isBuffer(e)) this._addBuffer(e, t);
    else if (e instanceof ee) this.chunks = this.chunks.concat(e.chunks);
    else if (ee._isScriptChunk(e)) this._insertAtPosition(e, t);
    else throw new Error("Invalid script chunk");
  }
  _insertAtPosition(e, t) {
    t ? this.chunks.unshift(e) : this.chunks.push(e);
  }
  _addOpcode(e, t) {
    let i;
    return typeof e == "number" ? i = e : e instanceof mt ? i = e.toNumber() : i = new mt(e).toNumber(), this._insertAtPosition({
      opcodenum: i
    }, t), this;
  }
  _addBuffer(e, t) {
    let i, o = e.length;
    if (o >= 0 && o < $.OP_PUSHDATA1) i = o;
    else if (o < Math.pow(2, 8)) i = $.OP_PUSHDATA1;
    else if (o < Math.pow(2, 16)) i = $.OP_PUSHDATA2;
    else if (o < Math.pow(2, 32)) i = $.OP_PUSHDATA4;
    else throw new Error("You can't push that much data");
    return this._insertAtPosition({
      buf: e,
      len: o,
      opcodenum: i
    }, t), this;
  }
  /**
  * Compares a script with another script
  */
  equals(e) {
    if (R.validateState(e instanceof ee, "Must provide another script"), this.chunks.length !== e.chunks.length) return !1;
    for (let t = 0; t < this.chunks.length; t++) {
      if (W.isBuffer(this.chunks[t].buf) && !W.isBuffer(e.chunks[t].buf) || W.isBuffer(this.chunks[t].buf) && !this.chunks[t].buf.equals(e.chunks[t].buf)) return !1;
      if (this.chunks[t].opcodenum !== e.chunks[t].opcodenum) return !1;
    }
    return !0;
  }
  /**
  * Analogous to nexad's FindAndDelete. Find and delete equivalent chunks,
  * typically used with push data chunks. Note that this will find and delete
  * not just the same data, but the same data with the same push data op as
  * produced by default. i.e., if a pushdata in a tx does not use the minimal
  * pushdata op, then when you try to remove the data it is pushing, it will not
  * be removed, because they do not use the same pushdata op.
  */
  findAndDelete(e) {
    let i = e.toBuffer().toString("hex");
    for (let o = 0; o < this.chunks.length; o++) {
      let c = new ee({
        chunks: [
          this.chunks[o]
        ]
      }).toBuffer().toString("hex");
      i === c && this.chunks.splice(o, 1);
    }
    return this;
  }
  /**
  * Comes from nexad's script interpreter CheckMinimalPush function
  * @returns true if the chunk {i} is the smallest way to push that particular data.
  */
  checkMinimalPush(e) {
    let t = this.chunks[e], i = t.buf, o = t.opcodenum;
    return i ? i.length === 0 ? o === $.OP_0 : i.length === 1 && i[0] >= 1 && i[0] <= 16 || i.length === 1 && i[0] === 129 ? !1 : i.length <= 75 ? o === i.length : i.length <= 255 ? o === $.OP_PUSHDATA1 : i.length <= 65535 ? o === $.OP_PUSHDATA2 : !0 : !0;
  }
  /**
  * Comes from bitcoind's script GetSigOpCount(boolean) function
  * @param accurate default true
  * @returns number of signature operations required by this script
  */
  getSignatureOperationsCount(e = !0) {
    let t = 0, i = $.OP_INVALIDOPCODE;
    return this.chunks.forEach((o) => {
      let a = o.opcodenum;
      a == $.OP_CHECKSIG || a == $.OP_CHECKSIGVERIFY ? t++ : (a == $.OP_CHECKMULTISIG || a == $.OP_CHECKMULTISIGVERIFY) && (e && i >= $.OP_1 && i <= $.OP_16 ? t += mt.decodeOP_N(i) : t += 20), i = a;
    }), t;
  }
  /**
  * @returns true if the script is only composed of data pushing
  * opcodes or small int opcodes (OP_0, OP_1, ..., OP_16)
  */
  isPushOnly() {
    return this.chunks.every((e) => e.opcodenum <= $.OP_16 || e.opcodenum === $.OP_PUSHDATA1 || e.opcodenum === $.OP_PUSHDATA2 || e.opcodenum === $.OP_PUSHDATA4);
  }
  /**
  * @returns true if this is a pay to script template output script
  * @remarks for well-known-1 template use {@link isPublicKeyTemplateOut}
  */
  isScriptTemplateOut() {
    if (this.chunks.length < 3) return !1;
    let e = this.chunks[0].opcodenum !== $.OP_0, t = e ? 4 : 3, i = e ? 2 : 1, o = e ? 3 : 2, a = this.chunks.length >= t && W.isHashBuffer(this.chunks[i].buf) && (W.isHashBuffer(this.chunks[o].buf) || this.chunks[o].opcodenum === $.OP_FALSE);
    return e && (a &&= !!(this.chunks[0].buf && this.chunks[0].buf.length >= 32 && // group id
    this.chunks[1].buf && this.chunks[1].buf.length >= 2 && this.chunks[1].buf.length <= 8)), a && this.chunks.length > t && (a = new ee({
      chunks: this.chunks.slice(t)
    }).isPushOnly()), a;
  }
  /**
  * Checks if this script is a valid pay to script template input script
  * 
  * @returns true if this is a pay to script template form input script
  * @remarks for well-known-1 template use {@link isPublicKeyTemplateIn}
  */
  isScriptTemplateIn() {
    return this.chunks.length > 1 && W.isBuffer(this.chunks[0].buf) && this.isPushOnly();
  }
  /**
  * @returns true if this is a pay to pubkey template output script (well-known-1, p2pkt)
  */
  isPublicKeyTemplateOut() {
    if (this.chunks.length < 3) return !1;
    let e = this.chunks[0].opcodenum !== $.OP_0, t = e ? 4 : 3, i = e ? 2 : 1, o = e ? 3 : 2, a = this.chunks.length === t && this.chunks[i].opcodenum === $.OP_1 && W.isHashBuffer(this.chunks[o].buf);
    return e && (a &&= !!(this.chunks[0].buf && this.chunks[0].buf.length >= 32 && // group id
    this.chunks[1].buf && this.chunks[1].buf.length >= 2 && this.chunks[1].buf.length <= 8)), a;
  }
  /**
  * @returns true if this is a pay to public key template input script
  */
  isPublicKeyTemplateIn() {
    if (this.chunks.length != 2) return !1;
    let e = this.chunks[0].buf, t = this.chunks[1].buf;
    if (t && t.length >= 64 && t.length <= 68 && e?.length === 34) {
      let i = ee.fromBuffer(e).chunks[0].buf;
      return i?.length === 33 && (i[0] === 3 || i[0] === 2);
    }
    return !1;
  }
  /**
  * @returns true if this is a pay to pubkey hash output script
  */
  isPublicKeyHashOut() {
    return !!(this.chunks.length === 5 && this.chunks[0].opcodenum === $.OP_DUP && this.chunks[1].opcodenum === $.OP_HASH160 && this.chunks[2].buf && this.chunks[2].buf.length === 20 && this.chunks[3].opcodenum === $.OP_EQUALVERIFY && this.chunks[4].opcodenum === $.OP_CHECKSIG);
  }
  /**
  * @returns {boolean} if this is a pay to public key hash input script
  */
  isPublicKeyHashIn() {
    if (this.chunks.length != 2) return !1;
    let e = this.chunks[0].buf, t = this.chunks[1].buf;
    if (e && e.length && t && t.length) {
      let i = t[0];
      if ((i === 4 || i === 6 || i === 7) && t.length === 65) return !0;
      if ((i === 3 || i === 2) && t.length === 33) return !0;
    }
    return !1;
  }
  /**
  * @returns true if this is a valid standard OP_RETURN output
  */
  isDataOut() {
    if (!(this.chunks.length >= 1 && this.chunks[0].opcodenum === $.OP_RETURN && this.toBuffer().length <= 223)) return !1;
    let t = this.chunks.slice(1);
    return new ee({
      chunks: t
    }).isPushOnly();
  }
  /**
  * @returns true if this is a valid Token Description OP_RETURN output
  */
  isTokenDescriptionOut() {
    return lr(this.chunks.length, 2, 8) && this.chunks[0].opcodenum === $.OP_RETURN && this.chunks[1].len === 4 && new ee({
      chunks: this.chunks.slice(1)
    }).isPushOnly();
  }
  /**
  * Will retrieve the Public Key buffer from p2pkt/p2pkh input scriptSig
  */
  getPublicKey() {
    return R.validateState(this.isPublicKeyHashIn() || this.isPublicKeyTemplateIn(), "Can't retrieve PublicKey from a non-PKT or non-PKH input"), this.isPublicKeyHashIn() ? this.chunks[1].buf : ee.fromBuffer(this.chunks[0].buf).chunks[0].buf;
  }
  /**
  * Will retrieve the Public Key Hash buffer from p2pkh output scriptPubKey
  */
  getPublicKeyHash() {
    return R.validateState(this.isPublicKeyHashOut(), "Can't retrieve PublicKeyHash from a non-PKH output"), this.chunks[2].buf;
  }
  /**
  * Will retrieve the Template Hash from p2pkt/p2st output scriptPubKey
  * 
  * @returns OP_1 if its p2pkt, otherwise the template hash buffer
  */
  getTemplateHash() {
    return R.validateState(this.isPublicKeyTemplateOut() || this.isScriptTemplateOut(), "Can't retrieve TemplateHash from a non-PST output"), this.isPublicKeyTemplateOut() ? $.OP_1 : this.chunks[0].opcodenum !== $.OP_0 ? this.chunks[2].buf : this.chunks[1].buf;
  }
  /**
  * Will retrieve the Constraint Hash from p2pkt/p2st output scriptPubKey
  * 
  * @returns The constraint hash buffer, or OP_FALSE if not included
  */
  getConstraintHash() {
    R.validateState(this.isPublicKeyTemplateOut() || this.isScriptTemplateOut(), "Can't retrieve ConstraintHash from a non-PST output");
    let t = this.chunks[0].opcodenum !== $.OP_0 ? 3 : 2;
    return this.isPublicKeyTemplateOut() ? this.chunks[t].buf : this.chunks[t].opcodenum === $.OP_FALSE ? $.OP_FALSE : this.chunks[t].buf;
  }
  /**
  * Will retrieve the Group Identifier number from Token Description OP_RETURN output
  * 
  * @remarks This method doesn't check if the group id number is fit to NRC1/NRC2 etc. 
  */
  getGroupIdType() {
    return R.validateState(this.isTokenDescriptionOut(), "Can't retrieve GroupIdType from a non Token Description output"), X.fromScriptNumBuffer(this.chunks[1].buf).toNumber();
  }
}
class Ue {
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
  constructor(e, t, i) {
    if (this.toNexaAddress = this.toString, this.toObject = this.toJSON, R.validateArgument(!ze(e), "First argument is required, please include address data."), e instanceof Ue) return e;
    if (te(e)) return Ue.fromString(e);
    R.validateArgument(W.isBuffer(e), "data must be Address, string or Buffer"), Ue.validateParams(t, i), this.data = e, this.network = Ie.get(t) || Ie.defaultNetwork, this.type = i || Ye.PayToScriptTemplate;
  }
  static validateParams(e, t) {
    if (e && !Ie.get(e)) throw new TypeError('Second argument must be "mainnet" or "testnet".');
    if (t && t !== Ye.PayToScriptTemplate && t !== Ye.GroupIdAddress && t !== Ye.PayToPublicKeyHash) throw new TypeError('Third argument must be "P2ST", "P2PKH" or "GROUP"');
  }
  /**
  * @param address string
  * 
  * @returns A new valid and frozen instance of an Address
  */
  static fromString(e) {
    R.validateArgument(te(e), "parameter supplied is not a string."), R.validateArgument(e.length > 34, "Invalid Address string provided");
    let t = ka.decode(e), i = Ie.get(t.prefix, "prefix");
    return new Ue(t.data, i, t.type);
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
    return ka.encode(this.network.prefix, this.type, this.data);
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
  static fromObject(e) {
    R.validateArgument(te(e?.data), "Must provide a `data` property"), R.validateArgument(te(e?.type), "Must provide a `type` property"), R.validateState(vt.isHexa(e.data), "Unexpected data property, expected to be hex.");
    let t = Buffer.from(e.data, "hex");
    return new Ue(t, e.network, e.type);
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
    return this.type === Ye.PayToPublicKeyHash;
  }
  /**
  * @return true if an address is of pay to script template type
  */
  isPayToScriptTemplate() {
    return this.type === Ye.PayToScriptTemplate;
  }
  /**
  * @return true if an address is a group token address
  */
  isGroupIdentifierAddress() {
    return this.type === Ye.GroupIdAddress;
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
  static getValidationError(e, t, i) {
    try {
      if (te(e)) {
        let o = Ue.fromString(e);
        if (e = o.data, t && Ie.get(t)?.prefix !== o.network.prefix) throw new Error("Address has mismatched network type.");
        if (t = o.network, i && i !== o.type) throw new Error("Address has mismatched type.");
        i = o.type;
      }
      this.validateParams(t, i), ka.encode(Ie.get(t)?.prefix || Ie.defaultNetwork.prefix, i || Ye.PayToScriptTemplate, e);
    } catch (o) {
      return o;
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
  static isValid(e, t, i) {
    return !Ue.getValidationError(e, t, i);
  }
  /**
  * Instantiate an address from a PublicKey instance
  *
  * @param pubkey the public key instance
  * @param network either a Network instance, 'mainnet' or 'testnet'
  * @param type address encoding type
  * @returns A new valid and frozen instance of an Address
  */
  static fromPublicKey(e, t, i) {
    let o = this._transformPublicKey(e, i);
    return new Ue(o, t, i);
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
  static fromScriptTemplate(e, t, i, o) {
    let a = Ue._transformScriptTemplate(e, t, i);
    return new Ue(a, o, Ye.PayToScriptTemplate);
  }
  /**
  * Internal function to transform a {@link PublicKey}
  */
  static _transformPublicKey(e, t = Ye.PayToScriptTemplate) {
    if (R.validateArgument(e instanceof Ke, "Address must be an instance of PublicKey."), t === Ye.PayToPublicKeyHash) return le.sha256ripemd160(e.toBuffer());
    if (t === Ye.PayToScriptTemplate) {
      let i = ee.empty().add(e.toBuffer()), o = le.sha256ripemd160(i.toBuffer());
      return Ue._transformScriptTemplate($.OP_1, o);
    } else throw new Error("type must be P2ST or P2PKH");
  }
  /**
  * Internal function to transform a Script Template params
  */
  static _transformScriptTemplate(e, t, i) {
    if (e != $.OP_1 && !W.isHashBuffer(e)) throw new TypeError("templateHash supplied is not a hash buffer or well-known OP_1.");
    if (t != $.OP_FALSE && !W.isHashBuffer(t)) throw new TypeError("constraintHash supplied is not a hash buffer or OP_FALSE.");
    let o = ee.empty().add($.OP_FALSE).add(e).add(t);
    return i && (rr(i) ? i.forEach((a) => o.add(a)) : i instanceof ee ? o.add(i) : vt.isHexa(i) && o.add(ee.fromHex(i))), new Je().writeVarLengthBuf(o.toBuffer()).toBuffer();
  }
  /**
  * Will return the transaction output type by the address type
  * 
  * @param address as string
  * @returns 1 - Template, 0 - otherwise
  */
  static getOutputType(e) {
    return this.fromString(e).getOutputType();
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
class gt {
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
  constructor(e) {
    if (this.toObject = this.toJSON, e instanceof gt) return e;
    if (ze(e) && (e = {
      bn: gt._getRandomBN(),
      compressed: !0,
      network: Ie.defaultNetwork
    }), !gt._isPrivateKeyParams(e)) throw new TypeError("First argument is an unrecognized data type.");
    if (!e.bn || e.bn.cmp(new X(0)) === 0) throw new TypeError("Number can not be equal to zero, undefined, null or false");
    if (!e.bn.lt(ye.getN())) throw new TypeError("Number must be less than N");
    this.bn = e.bn, this.compressed = oe(e.compressed) ? !0 : e.compressed, this.network = e.network || Ie.defaultNetwork;
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
  toAddress(e = Ye.PayToScriptTemplate) {
    return Ue.fromPublicKey(this.publicKey, this.network, e);
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
    let e;
    return this.compressed ? e = Buffer.concat([
      Buffer.from([
        this.network.privatekey
      ]),
      this.bn.toBuffer({
        size: 32
      }),
      Buffer.from([
        1
      ])
    ]) : e = Buffer.concat([
      Buffer.from([
        this.network.privatekey
      ]),
      this.bn.toBuffer({
        size: 32
      })
    ]), Ct.encode(e);
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
    return this._pubkey || (this._pubkey = Ke.fromPrivateKey(this)), this._pubkey;
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
    let e = this.compressed ? "" : ", uncompressed";
    return `<PrivateKey: ${this.toString()}, network: ${this.network}${e}>`;
  }
  /**
  * Instantiate a PrivateKey from a Buffer with the DER or WIF representation
  */
  static fromBuffer(e, t) {
    R.validateArgument(W.isBuffer(e), "First argument is expected to be a buffer.");
    let i = this._transformBuffer(e, t);
    return new gt(i);
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
  static fromWIF(e, t) {
    R.validateArgument(te(e), "First argument is expected to be a string.");
    let i;
    return vt.isHexa(e) ? i = {
      bn: new X(Buffer.from(e, "hex")),
      compressed: !0,
      network: Ie.get(t) || Ie.defaultNetwork
    } : i = gt._transformWIF(e, t), new gt(i);
  }
  static {
    this.fromObject = this.fromJSON;
  }
  /**
  * Instantiate a PrivateKey from a plain JavaScript object
  *
  * @param obj - The output from privateKey.toObject()
  */
  static fromJSON(e) {
    R.validateArgument(Oe(e), "First argument is expected to be an object.");
    let t = this._transformObject(e);
    return new gt(t);
  }
  /**
  * Instantiate a PrivateKey from random bytes
  *
  * @param network - Either "mainnet" or "testnet"
  * @returns A new valid instance of PrivateKey
  */
  static fromRandom(e) {
    let t = {
      bn: gt._getRandomBN(),
      compressed: !0,
      network: Ie.get(e) || Ie.defaultNetwork
    };
    return new gt(t);
  }
  /**
  * Check if there would be any errors when initializing a PrivateKey
  *
  * @param data - The encoded data in various formats
  * @param network - Either "mainnet" or "testnet"
  * @returns An error if exists
  */
  static getValidationError(e, t) {
    try {
      this.from(e, t);
    } catch (i) {
      return i;
    }
  }
  /**
  * Check if the parameters are valid
  *
  * @param data - The encoded data in various formats
  * @param network - Either "mainnet" or "testnet"
  * @returns true If the private key would be valid
  */
  static isValid(e, t) {
    return e ? !this.getValidationError(e, t) : !1;
  }
  /**
  * Helper to instantiate PrivateKey from different kinds of arguments.
  */
  static from(e, t) {
    if (ze(e)) return this.fromRandom(t);
    if (e instanceof gt) return e;
    if (e instanceof X) {
      let i = {
        bn: e,
        compressed: !0,
        network: Ie.get(t) || Ie.defaultNetwork
      };
      return new gt(i);
    } else {
      if (W.isBuffer(e)) return this.fromBuffer(e, t);
      if (this._isPrivateKeyParams(e) && e.bn && e.network) return this.fromObject(e);
      if (te(e)) return this.fromString(e, t);
      throw new TypeError("First argument is an unrecognized data type.");
    }
  }
  static _isPrivateKeyParams(e) {
    return Oe(e) && "bn" in e && "network" in e;
  }
  static _getRandomBN() {
    let e;
    do {
      let t = W.getRandomBuffer(32);
      e = X.fromBuffer(t);
    } while (!e.lt(ye.getN()));
    return e;
  }
  /**
  * Internal function to transform a WIF Buffer into a private key
  */
  static _transformBuffer(e, t) {
    if (e.length === 32) return {
      network: Ie.get(t) || Ie.defaultNetwork,
      bn: X.fromBuffer(e),
      compressed: !1
    };
    let i = {};
    if (i.network = Ie.get(e[0], "privatekey"), !i.network) throw new Error("Invalid network");
    if (t && i.network !== Ie.get(t)) throw new TypeError("Private key network mismatch");
    if (e.length === 34 && e[33] === 1) i.compressed = !0;
    else if (e.length === 33) i.compressed = !1;
    else throw new Error("Length of buffer must be 33 (uncompressed) or 34 (compressed)");
    return i.bn = X.fromBuffer(e.subarray(1, 33)), i;
  }
  /**
  * Internal function to transform a JSON object into a private key
  */
  static _transformObject(e) {
    return {
      bn: new X(e.bn, "hex"),
      network: Ie.get(e.network) || Ie.defaultNetwork,
      compressed: e.compressed
    };
  }
  /**
  * Internal function to transform a WIF string into a private key
  */
  static _transformWIF(e, t) {
    return this._transformBuffer(Ct.decode(e), t);
  }
}
class Ps extends Error {
  constructor(e) {
    super(`Invalid derivation argument: got ${e}`);
  }
}
class Oi extends Error {
  constructor(e) {
    super(`Invalid derivation path, it should look like: "m/1/100", got "${e}"`);
  }
}
class Tc extends Error {
  constructor(e, t) {
    super(`Invalid Base58 character: ${e} in ${t}`);
  }
}
class fn extends Error {
  constructor(e) {
    super(`Invalid Base58 checksum for ${e}`);
  }
}
class zc extends Error {
  constructor(e) {
    super(`Invalid length for xprivkey string in ${e}`);
  }
}
class Oc extends Error {
  constructor(e) {
    super(`Invalid version for network: got ${e}`);
  }
}
class Nc extends Error {
  constructor(e) {
    super(`Invalid network: must be "mainnet" or "testnet", got ${e}`);
  }
}
class Cc extends Error {
  constructor(e) {
    super(`Invalid entropy: must be an hexa string or binary buffer, got ${e}`);
  }
}
class Fc extends Error {
  constructor(e) {
    super(`Invalid entropy: more than 512 bits is non standard, got ${e}`);
  }
}
class Rc extends Error {
  constructor(e) {
    super(`Invalid entropy: at least 128 bits needed, got ${e}`);
  }
}
class Lc extends Error {
  constructor() {
    super("Argument is an extended private key");
  }
}
class Oo extends Error {
  constructor() {
    super("Invalid argument: creating a hardened path requires an HDPrivateKey");
  }
}
class re {
  static {
    this.Hardened = 2147483648;
  }
  static {
    this.MaxIndex = 2 * re.Hardened;
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
    this.VersionEnd = re.VersionStart + re.VersionSize;
  }
  static {
    this.DepthStart = re.VersionEnd;
  }
  static {
    this.DepthEnd = re.DepthStart + re.DepthSize;
  }
  static {
    this.ParentFingerPrintStart = re.DepthEnd;
  }
  static {
    this.ParentFingerPrintEnd = re.ParentFingerPrintStart + re.ParentFingerPrintSize;
  }
  static {
    this.ChildIndexStart = re.ParentFingerPrintEnd;
  }
  static {
    this.ChildIndexEnd = re.ChildIndexStart + re.ChildIndexSize;
  }
  static {
    this.ChainCodeStart = re.ChildIndexEnd;
  }
  static {
    this.ChainCodeEnd = re.ChainCodeStart + re.ChainCodeSize;
  }
  /**
  * Util function that splits a string path into a derivation index array.
  * It will return null if the string path is malformed.
  * It does not validate if indexes are in bounds.
  *
  * @param path
  */
  static getDerivationIndexes(e) {
    if (this.RootElementAlias.includes(e)) return [];
    let t = e.split("/");
    if (!this.RootElementAlias.includes(t[0])) return null;
    let i = t.slice(1).map((o) => {
      let a = o.slice(-1) === "'";
      if (a && (o = o.slice(0, -1)), !o || o[0] === "-") return NaN;
      let p = +o;
      return a && (p += this.Hardened), p;
    });
    return i.some(isNaN) ? null : i;
  }
  static _validateNetwork(e, t, i = !1) {
    let o = Ie.get(t);
    if (!o) return new Nc(t);
    let a = e.subarray(this.VersionStart, this.VersionEnd);
    return W.integerFromBuffer(a) !== (i ? o.xprivkey : o.xpubkey) ? new Oc(a) : null;
  }
  /**
  * Verifies that a given serialized hd key in base58 with checksum format
  * is valid.
  *
  * @param data - the serialized hd key
  * @param network - optional, if present, checks that the network provided matches the network serialized.
  */
  static isValidSerialized(e, t, i = !1) {
    return Zf(this.getSerializedError(e, t, i));
  }
  /**
  * Checks what's the error that causes the validation of a serialized public key
  * in base58 with checksum to fail.
  *
  * @param data - the serialized hd key
  * @param network - optional, if present, checks that the network provided matches the network serialized.
  */
  static getSerializedError(e, t, i = !1) {
    if (!(te(e) || W.isBuffer(e))) return new TypeError("Expected string or buffer");
    if (!er.validCharacters(e)) return new Tc("(unknown)", e);
    try {
      e = Ct.decode(e);
    } catch {
      return new fn(e);
    }
    if (e.length !== re.DataSize) return new zc(e);
    if (!oe(t)) {
      let o = this._validateNetwork(e, t, i);
      if (o) return o;
    }
    if (!i) {
      let o = W.integerFromBuffer(e.subarray(0, 4));
      if (o === Ie.mainnet.xprivkey || o === Ie.testnet.xprivkey) return new Lc();
    }
    return null;
  }
}
class Ft {
  static {
    this.PublicKeySize = 33;
  }
  static {
    this.PublicKeyStart = re.ChainCodeEnd;
  }
  static {
    this.PublicKeyEnd = this.PublicKeyStart + this.PublicKeySize;
  }
  static {
    this.ChecksumStart = this.PublicKeyEnd;
  }
  static {
    this.ChecksumEnd = this.ChecksumStart + re.CheckSumSize;
  }
  /**
  * The representation of an hierarchically derived public key.
  *
  * See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  *
  * @param arg
  */
  constructor(e) {
    if (this.toJSON = this.toObject, ze(e)) throw new TypeError("Must supply an argument to create a HDPublicKey");
    if (e instanceof Ft) return e;
    let t = Ft._classifyArgument(e);
    this.publicKey = t.publicKey, this.network = t.network, this.depth = t.depth, this.parentFingerPrint = t.parentFingerPrint, this.fingerPrint = t.fingerPrint, this.chainCode = t.chainCode, this.childIndex = t.childIndex, this.xpubkey = t.xpubkey, this.checksum = t.checksum;
  }
  static _classifyArgument(e) {
    if (te(e) || W.isBuffer(e)) {
      let t = e.toString();
      if (re.isValidSerialized(t)) return this._buildFromSerialized(t);
      throw re.getSerializedError(e);
    }
    if (this._isIHDPubKey(e)) return e;
    if (this._isMinimalDtoObject(e)) return this._buildFromMinimalObject(e);
    if (this._isDtoObject(e)) return this._buildFromObject(e);
    if (this._isIHDPrivKey(e)) return this._buildFromHDPrivateKey(e);
    throw new TypeError("Invalid argument type for creation, must be string, json, buffer, or object");
  }
  static _isDtoObject(e) {
    return Oe(e) && "xpubkey" in e && !("privateKey" in e) && "publicKey" in e && te(e.publicKey);
  }
  static _isMinimalDtoObject(e) {
    return Oe(e) && !("xpubkey" in e) && !("privateKey" in e) && "publicKey" in e && te(e.publicKey);
  }
  static _isIHDPubKey(e) {
    return Oe(e) && "xpubkey" in e && !("privateKey" in e) && "publicKey" in e && e.publicKey instanceof Ke;
  }
  static _isIHDPrivKey(e) {
    return Oe(e) && "privateKey" in e && Oe(e.privateKey) && "bn" in e.privateKey;
  }
  /**
  * Verifies that a given path is valid.
  *
  * @param arg
  * @return {boolean}
  */
  static isValidPath(e) {
    if (te(e)) {
      let t = re.getDerivationIndexes(e);
      return t !== null && t.every(Ft.isValidPath);
    }
    return Tt(e) ? e >= 0 && e < re.Hardened : !1;
  }
  /**
  * Create a HDPublicKey from a buffer argument
  *
  * @param buf
  */
  static fromBuffer(e) {
    return R.validateArgument(W.isBuffer(e), "No valid Buffer was provided"), new Ft(e);
  }
  /**
  * Return a buffer representation of the xpubkey
  */
  toBuffer() {
    return Buffer.from(this.xpubkey);
  }
  static fromString(e) {
    return R.validateArgument(te(e), "No valid string was provided"), new Ft(e);
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
  static fromObject(e) {
    return R.validateArgument(Oe(e), "No valid argument was provided"), new Ft(e);
  }
  static fromMinimalObject(e) {
    R.validateArgument(Oe(e), "No valid argument was provided");
    let t = this._buildFromMinimalObject(e);
    return new Ft(t);
  }
  /**
  * Returns a plain JavaScript object with information to reconstruct a key.
  */
  toObject() {
    return {
      network: this.network.name,
      depth: this.depth,
      fingerPrint: W.integerFromBuffer(this.fingerPrint),
      parentFingerPrint: W.integerFromBuffer(this.parentFingerPrint),
      childIndex: this.childIndex,
      chainCode: this.chainCode.toString("hex"),
      publicKey: this.publicKey.toString(),
      checksum: W.integerFromBuffer(this.checksum),
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
  toAddress(e = Ye.PayToScriptTemplate) {
    return Ue.fromPublicKey(this.publicKey, this.network, e);
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
  deriveChild(e, t) {
    if (Tt(e)) return this._deriveWithNumber(e, t);
    if (te(e)) return this._deriveFromString(e);
    throw new Ps(e);
  }
  _deriveWithNumber(e, t) {
    if (e >= re.Hardened || t) throw new Oo();
    if (e < 0) throw new Oi(e);
    let i = W.integerAsBuffer(e), o = Buffer.concat([
      this.publicKey.toBuffer(),
      i
    ]), a = le.sha512hmac(o, this.chainCode), p = X.fromBuffer(a.subarray(0, 32), {
      size: 32
    }), c = a.subarray(32, 64), g;
    try {
      g = Ke.fromPoint(ye.getG().mul(p).add(this.publicKey.point));
    } catch {
      return this._deriveWithNumber(e + 1);
    }
    let h = {
      version: W.integerAsBuffer(this.network.xpubkey),
      depth: W.integerAsSingleByteBuffer(this.depth + 1),
      parentFingerPrint: this.fingerPrint,
      childIndex: W.integerAsBuffer(e),
      publicKey: g.toBuffer(),
      chainCode: c
    }, m = Ft._buildFromBuffers(h);
    return new Ft(m);
  }
  _deriveFromString(e) {
    if (e.includes("'")) throw new Oo();
    if (!Ft.isValidPath(e)) throw new Oi(e);
    const t = (o, a) => a.reduce((p, c) => p._deriveWithNumber(c), o);
    let i = re.getDerivationIndexes(e);
    return t(this, i);
  }
  static _buildFromObject(e) {
    return {
      network: Ie.get(e.network),
      depth: e.depth,
      fingerPrint: W.integerAsBuffer(e.fingerPrint),
      parentFingerPrint: W.integerAsBuffer(e.parentFingerPrint),
      childIndex: e.childIndex,
      chainCode: Buffer.from(e.chainCode, "hex"),
      xpubkey: e.xpubkey,
      checksum: W.integerAsBuffer(e.checksum),
      publicKey: Ke.fromString(e.publicKey, void 0, Ie.get(e.network))
    };
  }
  static _buildFromMinimalObject(e) {
    let t = {
      version: W.integerAsBuffer(Ie.get(e.network).xpubkey),
      depth: W.integerAsSingleByteBuffer(e.depth),
      parentFingerPrint: W.integerAsBuffer(e.parentFingerPrint),
      childIndex: W.integerAsBuffer(e.childIndex),
      chainCode: Buffer.from(e.chainCode, "hex"),
      publicKey: Buffer.from(e.publicKey, "hex")
    };
    return this._buildFromBuffers(t);
  }
  static _buildFromHDPrivateKey(e) {
    let t = ye.getG().mul(e.privateKey.bn), i = {
      version: W.integerAsBuffer(e.network.xpubkey),
      depth: W.integerAsSingleByteBuffer(e.depth),
      parentFingerPrint: e.parentFingerPrint,
      childIndex: W.integerAsBuffer(e.childIndex),
      chainCode: e.chainCode,
      publicKey: ye.pointToCompressed(t)
    };
    return this._buildFromBuffers(i);
  }
  static _buildFromSerialized(e) {
    let t = Ct.decode(e), i = {
      version: t.subarray(re.VersionStart, re.VersionEnd),
      depth: t.subarray(re.DepthStart, re.DepthEnd),
      parentFingerPrint: t.subarray(re.ParentFingerPrintStart, re.ParentFingerPrintEnd),
      childIndex: t.subarray(re.ChildIndexStart, re.ChildIndexEnd),
      chainCode: t.subarray(re.ChainCodeStart, re.ChainCodeEnd),
      publicKey: t.subarray(this.PublicKeyStart, this.PublicKeyEnd),
      checksum: t.subarray(this.ChecksumStart, this.ChecksumEnd)
    };
    return this._buildFromBuffers(i);
  }
  /**
  * Receives a object with buffers in all the properties and populates the
  * internal structure
  *
  * @param arg
  */
  static _buildFromBuffers(e) {
    Ft._validateBufferArguments(e);
    let t = [
      e.version,
      e.depth,
      e.parentFingerPrint,
      e.childIndex,
      e.chainCode,
      e.publicKey
    ], i = Buffer.concat(t), o = Ct.checksum(i);
    if (!e.checksum || !e.checksum.length) e.checksum = o;
    else if (e.checksum.toString("hex") !== o.toString("hex")) throw new fn(i);
    let a = Ie.get(W.integerFromBuffer(e.version)), p = Ke.fromBuffer(e.publicKey, !0, a);
    return {
      xpubkey: Ct.encode(i),
      network: a,
      depth: W.integerFromSingleByteBuffer(e.depth),
      publicKey: p,
      fingerPrint: le.sha256ripemd160(p.toBuffer()).subarray(0, re.ParentFingerPrintSize),
      chainCode: e.chainCode,
      childIndex: W.integerFromBuffer(e.childIndex),
      parentFingerPrint: e.parentFingerPrint,
      checksum: e.checksum
    };
  }
  static _validateBufferArguments(e) {
    const t = (i, o) => {
      let a = e[i];
      R.validateArgument(W.isBuffer(a), i + ` argument is not a buffer, it's ${typeof a}`), R.validateArgument(a.length === o, i + " has not the expected size: found " + a.length + ", expected " + o);
    };
    t("version", re.VersionSize), t("depth", re.DepthSize), t("parentFingerPrint", re.ParentFingerPrintSize), t("childIndex", re.ChildIndexSize), t("chainCode", re.ChainCodeSize), t("publicKey", Ft.PublicKeySize), e.checksum?.length && t("checksum", re.CheckSumSize);
  }
}
class wt {
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
    this.PrivateKeyStart = re.ChainCodeEnd + 1;
  }
  static {
    this.PrivateKeyEnd = this.PrivateKeyStart + this.PrivateKeySize;
  }
  static {
    this.ChecksumStart = this.PrivateKeyEnd;
  }
  static {
    this.ChecksumEnd = this.ChecksumStart + re.CheckSumSize;
  }
  /**
  * Represents an instance of an hierarchically derived private key.
  *
  * More info on https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  */
  constructor(e) {
    if (this.toJSON = this.toObject, e instanceof wt) return e;
    let t = wt._classifyArgument(e);
    this.privateKey = t.privateKey, this.publicKey = t.publicKey ?? t.privateKey.toPublicKey(), this.network = t.network, this.depth = t.depth, this.parentFingerPrint = t.parentFingerPrint, this.fingerPrint = t.fingerPrint, this.chainCode = t.chainCode, this.childIndex = t.childIndex, this.xprivkey = t.xprivkey, this.checksum = t.checksum;
  }
  static _classifyArgument(e) {
    if (!e) return this._generateRandomly();
    if (Ie.get(e)) return this._generateRandomly(e);
    if (te(e) || W.isBuffer(e)) {
      let t = e.toString();
      if (re.isValidSerialized(t, void 0, !0)) return this._buildFromSerialized(t);
      if (vt.isValidJSON(e)) return this._buildFromObject(JSON.parse(e));
      throw re.getSerializedError(e, void 0, !0);
    }
    if (this._isIHDPrivKey(e)) return e;
    if (this._isMinimalDtoObject(e)) return this._buildFromMinimalObject(e);
    if (this._isDtoObject(e)) return this._buildFromObject(e);
    throw new TypeError("Invalid argument type for creation, must be string, json, buffer, or object");
  }
  get hdPublicKey() {
    return this.getHDPublicKey();
  }
  get xpubkey() {
    return this.getHDPublicKey().xpubkey;
  }
  static _isDtoObject(e) {
    return Oe(e) && "xprivkey" in e && "privateKey" in e && te(e.privateKey);
  }
  static _isMinimalDtoObject(e) {
    return Oe(e) && !("xprivkey" in e) && "privateKey" in e && te(e.privateKey);
  }
  static _isIHDPrivKey(e) {
    return Oe(e) && "xprivkey" in e && "privateKey" in e && e.privateKey instanceof gt;
  }
  /**
  * Verifies that a given path is valid.
  *
  * @param arg
  * @param hardened
  */
  static isValidPath(e, t) {
    if (te(e)) {
      let i = re.getDerivationIndexes(e);
      return i !== null && i.every((o) => this.isValidPath(o));
    }
    return Tt(e) ? (e < re.Hardened && t === !0 && (e += re.Hardened), e >= 0 && e < re.MaxIndex) : !1;
  }
  static fromString(e) {
    return R.validateArgument(te(e), "No valid string was provided"), new wt(e);
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
  static fromBuffer(e) {
    return R.validateArgument(W.isBuffer(e), "No valid Buffer was provided"), new wt(e);
  }
  /**
  * Returns a buffer representation of the HDPrivateKey
  */
  toBuffer() {
    return Buffer.from(this.xprivkey);
  }
  /**
  * Returns a plain object with a representation of this private key.
  */
  toObject() {
    return {
      network: this.network.name,
      depth: this.depth,
      fingerPrint: W.integerFromBuffer(this.fingerPrint),
      parentFingerPrint: W.integerFromBuffer(this.parentFingerPrint),
      childIndex: this.childIndex,
      chainCode: this.chainCode.toString("hex"),
      privateKey: this.privateKey.toString(),
      checksum: W.integerFromBuffer(this.checksum),
      xprivkey: this.xprivkey
    };
  }
  static fromObject(e) {
    return R.validateArgument(Oe(e), "No valid argument was provided"), new wt(e);
  }
  static fromMinimalObject(e) {
    R.validateArgument(Oe(e), "No valid argument was provided");
    let t = this._buildFromMinimalObject(e);
    return new wt(t);
  }
  /**
  * Generate a private key from a seed, as described in BIP32
  *
  * @param seed
  * @param network
  * @return HDPrivateKey
  */
  static fromSeed(e, t = Ie.defaultNetwork) {
    let i = this._buildFromSeed(e, t);
    return new wt(i);
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
  deriveChild(e, t) {
    if (Tt(e)) return this._deriveWithNumber(e, t);
    if (te(e)) return this._deriveFromString(e);
    throw new Ps(e);
  }
  _deriveWithNumber(e, t) {
    if (!wt.isValidPath(e, t)) throw new Oi(e);
    t = e >= re.Hardened ? !0 : t, e < re.Hardened && t === !0 && (e += re.Hardened);
    let i = W.integerAsBuffer(e), o;
    if (t) {
      let S = this.privateKey.toBuffer();
      R.validateState(S.length === 32, "length of private key buffer is expected to be 32 bytes"), o = Buffer.concat([
        Buffer.from([
          0
        ]),
        S,
        i
      ]);
    } else o = Buffer.concat([
      this.publicKey.toBuffer(),
      i
    ]);
    let a = le.sha512hmac(o, this.chainCode), p = X.fromBuffer(a.subarray(0, 32), {
      size: 32
    }), c = a.subarray(32, 64), g = p.add(this.privateKey.toBigNumber()).umod(ye.getN()).toBuffer({
      size: 32
    });
    if (!gt.isValid(g))
      return this._deriveWithNumber(e + 1);
    let h = {
      version: W.integerAsBuffer(this.network.xprivkey),
      depth: W.integerAsSingleByteBuffer(this.depth + 1),
      parentFingerPrint: this.fingerPrint,
      childIndex: W.integerAsBuffer(e),
      privateKey: g,
      chainCode: c
    }, m = wt._buildFromBuffers(h);
    return new wt(m);
  }
  _deriveFromString(e) {
    if (!wt.isValidPath(e)) throw new Oi(e);
    const t = (o, a) => a.reduce((p, c) => p._deriveWithNumber(c), o);
    let i = re.getDerivationIndexes(e);
    return t(this, i);
  }
  static _buildFromSeed(e, t = Ie.defaultNetwork) {
    if (vt.isHexa(e) && (e = Buffer.from(e, "hex")), !Buffer.isBuffer(e)) throw new Cc(e);
    if (e.length < this.MINIMUM_ENTROPY_BITS * this.BITS_TO_BYTES) throw new Rc(e);
    if (e.length > this.MAXIMUM_ENTROPY_BITS * this.BITS_TO_BYTES) throw new Fc(e);
    let i = le.sha512hmac(e, Buffer.from("Bitcoin seed")), o = {
      version: W.integerAsBuffer((Ie.get(t) || Ie.defaultNetwork).xprivkey),
      depth: W.integerAsSingleByteBuffer(0),
      parentFingerPrint: W.integerAsBuffer(0),
      childIndex: W.integerAsBuffer(0),
      privateKey: i.subarray(0, 32),
      chainCode: i.subarray(32, 64)
    };
    return this._buildFromBuffers(o);
  }
  static _buildFromObject(e) {
    return {
      network: Ie.get(e.network),
      depth: e.depth,
      fingerPrint: W.integerAsBuffer(e.fingerPrint),
      parentFingerPrint: W.integerAsBuffer(e.parentFingerPrint),
      childIndex: e.childIndex,
      chainCode: Buffer.from(e.chainCode, "hex"),
      xprivkey: e.xprivkey,
      checksum: W.integerAsBuffer(e.checksum),
      privateKey: gt.fromString(e.privateKey, e.network)
    };
  }
  static _buildFromMinimalObject(e) {
    let t = {
      version: W.integerAsBuffer(Ie.get(e.network).xprivkey),
      depth: W.integerAsSingleByteBuffer(e.depth),
      parentFingerPrint: W.integerAsBuffer(e.parentFingerPrint),
      childIndex: W.integerAsBuffer(e.childIndex),
      chainCode: Buffer.from(e.chainCode, "hex"),
      privateKey: Buffer.from(e.privateKey, "hex")
    };
    return this._buildFromBuffers(t);
  }
  static _buildFromSerialized(e) {
    let t = Ct.decode(e), i = {
      version: t.subarray(re.VersionStart, re.VersionEnd),
      depth: t.subarray(re.DepthStart, re.DepthEnd),
      parentFingerPrint: t.subarray(re.ParentFingerPrintStart, re.ParentFingerPrintEnd),
      childIndex: t.subarray(re.ChildIndexStart, re.ChildIndexEnd),
      chainCode: t.subarray(re.ChainCodeStart, re.ChainCodeEnd),
      privateKey: t.subarray(this.PrivateKeyStart, this.PrivateKeyEnd),
      checksum: t.subarray(this.ChecksumStart, this.ChecksumEnd)
    };
    return this._buildFromBuffers(i);
  }
  /**
  * Receives a object with buffers in all the properties and populates the
  * internal structure
  */
  static _buildFromBuffers(e) {
    wt._validateBufferArguments(e);
    let t = [
      e.version,
      e.depth,
      e.parentFingerPrint,
      e.childIndex,
      e.chainCode,
      Buffer.alloc(1),
      e.privateKey
    ], i = Buffer.concat(t);
    if (!e.checksum?.length) e.checksum = Ct.checksum(i);
    else if (e.checksum.toString() !== Ct.checksum(i).toString()) throw new fn(i);
    let o = Ie.get(W.integerFromBuffer(e.version)), a = gt.from(X.fromBuffer(e.privateKey), o), p = a.toPublicKey();
    return {
      xprivkey: Ct.encode(i),
      network: o,
      depth: W.integerFromSingleByteBuffer(e.depth),
      privateKey: a,
      publicKey: p,
      fingerPrint: le.sha256ripemd160(p.toBuffer()).subarray(0, re.ParentFingerPrintSize),
      chainCode: e.chainCode,
      childIndex: W.integerFromBuffer(e.childIndex),
      parentFingerPrint: e.parentFingerPrint,
      checksum: e.checksum
    };
  }
  static _validateBufferArguments(e) {
    const t = (i, o) => {
      let a = e[i];
      R.validateArgument(W.isBuffer(a), i + " argument is not a buffer"), R.validateArgument(a.length === o, i + " has not the expected size: found " + a.length + ", expected " + o);
    };
    t("version", re.VersionSize), t("depth", re.DepthSize), t("parentFingerPrint", re.ParentFingerPrintSize), t("childIndex", re.ChildIndexSize), t("chainCode", re.ChainCodeSize), t("privateKey", this.PrivateKeySize), e.checksum?.length && t("checksum", re.CheckSumSize);
  }
  static _generateRandomly(e) {
    return this._buildFromSeed(W.getRandomBuffer(64), e);
  }
  /**
  * Will return the corresponding hd public key
  *
  * @returns An extended public key generated from the hd private key
  */
  getHDPublicKey() {
    return this._hdPublicKey || (this._hdPublicKey = new Ft(this)), this._hdPublicKey;
  }
  /**
  * Returns the console representation of this extended private key.
  */
  inspect() {
    return `<HDPrivateKey: ${this}>`;
  }
}
class tr {
  static {
    this.MAGIC_BYTES = Buffer.from(`Bitcoin Signed Message:
`);
  }
  constructor(e) {
    R.validateArgument(te(e), "First argument should be a string"), this.message = e;
  }
  /**
  * Will sign a message with a given private key.
  *
  * @param privateKey An instance of PrivateKey
  * @returns A base64 encoded compact signature
  */
  sign(e) {
    return this._sign(e).toCompact().toString("base64");
  }
  /**
  * Will return a boolean of the signature is valid for a given nexa address.
  * If it isn't valid, the specific reason is accessible via the "error" member.
  *
  * @param nexaAddress A nexa address
  * @param signatureString A base64 encoded compact signature
  */
  verify(e, t) {
    R.validateArgument(!ze(e), "nexaAddress"), R.validateArgument(te(t) && t.length > 0, "signatureString"), te(e) && (e = Ue.fromString(e));
    let i = Nt.fromCompact(Buffer.from(t, "base64")), o = new pr();
    o.hashbuf = this._magicHash(), o.sig = i;
    let a = o.toPublicKey(), p = Ue.fromPublicKey(a, e.network, e.type);
    return e.toString() !== p.toString() ? (this.error = "The signature did not match the message digest", !1) : this._verify(a, i);
  }
  _sign(e) {
    R.validateArgument(e instanceof gt, "First argument should be an instance of PrivateKey");
    let t = this._magicHash(), i = new pr();
    return i.hashbuf = t, i.privkey = e, i.pubkey = e.toPublicKey(), i.signRandomK(), i.calcI(), i.sig;
  }
  _magicHash() {
    let e = Je.varintBufNum(tr.MAGIC_BYTES.length), t = Buffer.from(this.message), i = Je.varintBufNum(t.length), o = Buffer.concat([
      e,
      tr.MAGIC_BYTES,
      i,
      t
    ]);
    return le.sha256sha256(o);
  }
  _verify(e, t) {
    R.validateArgument(e instanceof Ke, "First argument should be an instance of PublicKey"), R.validateArgument(t instanceof Nt, "Second argument should be an instance of Signature");
    let i = this._magicHash(), o = pr.verify(i, t, e);
    return o || (this.error = "The signature was invalid"), o;
  }
  /**
  * Instantiate a message from a message string
  *
  * @param str A string of the message
  * @returns A new instance of a Message
  */
  static fromString(e) {
    return new tr(e);
  }
  /**
  * Instantiate a message from JSON
  *
  * @param json An JSON string or Object with keys: message
  * @returns A new instance of a Message
  */
  static fromJSON(e) {
    return vt.isValidJSON(e) && (e = JSON.parse(e)), new tr(e.message);
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
var bi = /* @__PURE__ */ (function(r) {
  return r[r.LEGACY = 88888888] = "LEGACY", r[r.NRC1 = 88888890] = "NRC1", r[r.NRC2 = 88888891] = "NRC2", r[r.NRC3 = 88888892] = "NRC3", r;
})({});
const hr = {
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
}, No = hr.AUTHORITY | hr.MINT | hr.MELT | hr.BATON | hr.RESCRIPT | hr.SUBGROUP;
class ge {
  static {
    this.PARENT_GROUP_ID_SIZE = 32;
  }
  static {
    this.authFlags = {
      ...hr,
      ACTIVE_FLAG_BITS: (
        /** Has all permissions */
        No
      ),
      RESERVED_FLAG_BITS: No & ~hr.ALL_FLAG_BITS
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
  static findGroupId(e, t, i, o = 0) {
    let a, p = 0, c = 0n;
    te(e) && (e = Buffer.from(e, "hex").reverse()), t instanceof ee && (t = t.toBuffer());
    do {
      let g = new Je();
      c += 1n, c = c & ~this.authFlags.ALL_FLAG_BITS | i, g.write(e), t != null && g.writeVarLengthBuf(t), g.writeUInt64LEBN(X.fromBigInt(c)), a = le.sha256sha256(g.toBuffer()), p = a[30] << 8 | a[31];
    } while (p != o);
    return {
      hashBuffer: a,
      nonce: c
    };
  }
  static _getGroupAddressBuffer(e) {
    if (W.isBuffer(e)) return e;
    if (vt.isHexa(e)) return Buffer.from(e, "hex");
    let t = new Ue(e);
    return R.validateArgument(t.isGroupIdentifierAddress(), "Invalid group address"), t.data;
  }
  /**
  * Translates a group and additional data into a subgroup identifier
  *
  * @param group the group/token address or data buffer
  * @param data the additional data
  * 
  * @returns the subgroup id buffer
  */
  static generateSubgroupId(e, t) {
    if (R.validateArgument(!oe(e), "group is missing"), R.validateArgument(!oe(t), "data is missing"), e = this._getGroupAddressBuffer(e), W.isBuffer(t)) return Buffer.concat([
      e,
      t
    ]);
    if (Tt(t)) {
      let i = X.fromNumber(t).toBuffer({
        size: 8,
        endian: "little"
      });
      return Buffer.concat([
        e,
        i
      ]);
    }
    return vt.isHexa(t) ? Buffer.concat([
      e,
      Buffer.from(t, "hex")
    ]) : Buffer.concat([
      e,
      Buffer.from(t)
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
  static getParentGroupId(e) {
    let t = this._getGroupAddressBuffer(e);
    if (t.length < this.PARENT_GROUP_ID_SIZE) throw new Error("Invalid subgroup");
    return Buffer.from(t.subarray(0, 32));
  }
  /**
  * Get group amount buffer from BigInt to include in output script
  *
  * @param amount
  */
  static getAmountBuffer(e) {
    let t = new Je();
    if (e < 0n) {
      let i = X.fromBigInt(BigInt.asUintN(64, e));
      t.writeUInt64LEBN(i);
    } else if (e < 0x10000n) t.writeUInt16LE(Number(e));
    else if (e < 0x100000000n) t.writeUInt32LE(Number(e));
    else {
      let i = X.fromBigInt(e);
      t.writeUInt64LEBN(i);
    }
    return t.toBuffer();
  }
  /**
  * Get group amount value from Buffer
  *
  * @param amountBuf the amount buffer
  * @param unsigned return value as unsigned bigint, default to false
  */
  static getAmountValue(e, t = !1) {
    let i = X.fromBuffer(e, {
      endian: "little"
    }).toBigInt();
    return t ? i : BigInt.asIntN(64, i);
  }
  /**
  * @param authFlag the utxo group quantity/authority
  * @returns the nonce
  */
  static getNonce(e) {
    return e = BigInt.asUintN(64, e), e & ~this.authFlags.ALL_FLAG_BITS;
  }
  /**
  * Check if the group id has the flag
  * 
  * @param groupId the group id address or data buffer
  * @param groupIdFlag the group id flag
  * @returns true if this group id has the flag
  */
  static hasIdFlag(e, t) {
    return e = this._getGroupAddressBuffer(e), e.length >= this.PARENT_GROUP_ID_SIZE ? ((e[30] << 8 | e[31]) & t) == t : !1;
  }
  /**
  * Check if this authority and flag fit to this group creation
  * 
  * @param groupId the group id address or data buffer
  * @param authFlag the output group quantity/authority
  * @param groupIdFlag optional. the group id flag
  * @returns true if this is group creation data
  */
  static isGroupCreation(e, t, i = 0) {
    e = this._getGroupAddressBuffer(e), t = BigInt.asUintN(64, t);
    let o = this.getNonce(t) != 0n, a = this.isAuthority(t), p = this.hasIdFlag(e, i);
    return a && o && p;
  }
  /**
  * Check if this group is is subgroup
  * 
  * @param groupId the group id address or data buffer
  * @returns true if this group id is subgroup
  */
  static isSubgroup(e) {
    return e = this._getGroupAddressBuffer(e), e.length > this.PARENT_GROUP_ID_SIZE;
  }
  /**
  * Check if the group quantity/authority is Authority flag
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this is authority flag
  */
  static isAuthority(e) {
    return (e & this.authFlags.AUTHORITY) == this.authFlags.AUTHORITY;
  }
  /**
  * Check if the group quantity/authority allows minting
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this flag allows minting.
  */
  static allowsMint(e) {
    return (e & (ge.authFlags.AUTHORITY | ge.authFlags.MINT)) == (ge.authFlags.AUTHORITY | ge.authFlags.MINT);
  }
  /**
  * Check if the group quantity/authority allows melting
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this flag allows melting.
  */
  static allowsMelt(e) {
    return (e & (ge.authFlags.AUTHORITY | ge.authFlags.MELT)) == (ge.authFlags.AUTHORITY | ge.authFlags.MELT);
  }
  /**
  * Check if the group quantity/authority allows creation of new authorities
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this flag allows creation of authorities.
  */
  static allowsRenew(e) {
    return (e & (ge.authFlags.AUTHORITY | ge.authFlags.BATON)) == (ge.authFlags.AUTHORITY | ge.authFlags.BATON);
  }
  /**
  * Check if the group quantity/authority allows rescript
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this flag allows rescripting.
  */
  static allowsRescript(e) {
    return (e & (ge.authFlags.AUTHORITY | ge.authFlags.RESCRIPT)) == (ge.authFlags.AUTHORITY | ge.authFlags.RESCRIPT);
  }
  /**
  * Check if the group quantity/authority allows creation of subgroups
  * 
  * @param authFlag the output group quantity/authority
  * @returns true if this flag allows subgroups
  */
  static allowsSubgroup(e) {
    return (e & (ge.authFlags.AUTHORITY | ge.authFlags.SUBGROUP)) == (ge.authFlags.AUTHORITY | ge.authFlags.SUBGROUP);
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
  static verifyJsonDoc(e, t, i) {
    R.validateArgument(!Kt(e), "jsonDoc is missing"), R.validateArgument(!Kt(t), "group is missing");
    let o = e.substring(e.indexOf("{"), e.lastIndexOf("}") + 1);
    return (oe(i) || Kt(i)) && (i = JSON.parse(e)[1]), new tr(o).verify(t, i);
  }
  /**
  * Sign token description document json
  *
  * @param jsonDoc the json TDD as string
  * @param privKey private key to sign on the doc
  * 
  * @returns the signature string
  */
  static signJsonDoc(e, t) {
    R.validateArgument(!Kt(e), "jsonDoc is missing");
    let i = e.substring(e.indexOf("{"), e.lastIndexOf("}") + 1);
    return new tr(i).sign(t);
  }
}
class Et {
  /**
  * @param to destination address or public key
  * @param groupId group id buffer or group address or hex id - only if its token output script
  * @param groupAmount optional. quantity amount buffer or bigint - only if its token output script
  * 
  * @returns a new pay to public key / script template output for the given address or public key
  */
  static buildScriptTemplateOut(e, t, i) {
    if (R.validateArgument(!oe(e), "to", "must provide an argument"), R.validateArgument(e instanceof Ke || e instanceof Ue || te(e), "to", "must be address or pubkey"), R.validateArgument(ze(t) && ze(i) || !ze(t) && !ze(i), "group data", "both must present or both not present"), e = this.parseAddress(e), R.validateArgument(e.isPayToScriptTemplate(), "Invalid destination address (not a script template)"), te(t))
      if (vt.isHexa(t)) t = Buffer.from(t, "hex");
      else {
        let p = Ue.fromString(t);
        R.validateArgument(p.isGroupIdentifierAddress(), "Invalid group id address (not a group)"), t = p.data;
      }
    else t instanceof Ue && (R.validateArgument(t.isGroupIdentifierAddress(), "Invalid group id address (not a group)"), t = t.data);
    typeof i == "bigint" && (i = ge.getAmountBuffer(i));
    let o = new Ui(e.data).readVarLengthBuffer(), a = ee.fromBuffer(o);
    return !ze(t) && !ze(i) && (R.validateArgument(W.isBuffer(t), "groupId"), R.validateArgument(W.isBuffer(i), "groupAmount"), a.chunks = a.chunks.slice(1), a.prepend(i).prepend(t)), a;
  }
  /**
  * @param data the data to embed in the output
  * @param encoding the type of encoding of the string
  * 
  * @returns a new OP_RETURN script with data
  */
  static buildDataOut(e, t) {
    R.validateArgument(oe(e) || te(e) || W.isBuffer(e) || e instanceof ee, "data"), te(e) && (e = Buffer.from(e, t));
    let i = ee.empty().add($.OP_RETURN);
    return oe(e) || i.add(e), i;
  }
  /**
  * @param address the pay to address
  * @param groupId optional. only for p2st addresses
  * @param groupAmount optional. only for p2st addresses
  * 
  * @return an output script built from the address
  */
  static buildOutFromAddress(e, t, i) {
    if (te(e) && (e = Ue.fromString(e)), e.isPayToPublicKeyHash()) return this.buildPublicKeyHashOut(e);
    if (e.isPayToScriptTemplate()) return this.buildScriptTemplateOut(e, t, i);
    throw new Error(`Invalid address type: ${e.type}`);
  }
  /**
  * Builds a scriptSig (a script for an input) that signs a script template
  * output script.
  *
  * @param template the template script or OP_1 for well-known
  * @param constraint the constraint script or OP_FALSE
  * @param satisfier the satisfier script or buffer
  */
  static buildScriptTemplateIn(e, t, i) {
    R.validateArgument(e instanceof ee || e === $.OP_1, "template"), R.validateArgument(t instanceof ee || t === $.OP_FALSE, "constraint"), R.validateArgument(i instanceof ee || W.isBuffer(i), "satisfier");
    let o = ee.empty();
    return e instanceof ee && o.add(e.toBuffer()), t instanceof ee && o.add(t.toBuffer()), W.isBuffer(i) && (i = ee.fromBuffer(i)), o.add(i), o;
  }
  static parseAddress(e, t) {
    return te(e) ? Ue.fromString(e) : e instanceof Ke ? Ue.fromPublicKey(e, e.network, t) : e;
  }
  /**
  * @param to - destination address or public key
  * 
  * @returns a new pay to public key hash output for the given
  * address or public key
  */
  static buildPublicKeyHashOut(e) {
    return R.validateArgument(!oe(e), "to", "must provide an argument"), R.validateArgument(e instanceof Ke || e instanceof Ue || te(e), "to", "must be address or pubkey"), e = this.parseAddress(e, Ye.PayToPublicKeyHash), ee.empty().add($.OP_DUP).add($.OP_HASH160).add(e.data).add($.OP_EQUALVERIFY).add($.OP_CHECKSIG);
  }
  /**
  * Builds a scriptSig (a script for an input) that signs a public key hash
  * output script. (SIGHASH_ALL only)
  *
  * @param publicKey
  * @param signature a Signature object, or the signature in DER canonical encoding
  */
  static buildPublicKeyHashIn(e, t) {
    return R.validateArgument(e instanceof Ke, "publicKey"), R.validateArgument(t instanceof Nt || W.isBuffer(t), "signature"), t instanceof Nt && (t = t.toBuffer()), ee.empty().add(t).add(e.toBuffer());
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
  static buildTokenDescriptionLegacy(e, t, i, o, a) {
    R.validateArgument(te(e) && lr(e.length, 1, 9), "Ticker must be between 1-8 chars"), R.validateArgument(te(t) && !Kt(t), "Name is missing");
    let p = ee.empty().add($.OP_RETURN).add(X.fromNumber(bi.LEGACY).toScriptNumBuffer()).add(Buffer.from(e)).add(Buffer.from(t));
    return i && i.length > 0 ? (new URL(i), R.validateArgument(te(o) && !Kt(o), "You must include document hash if you set document url"), p.add(Buffer.from(i)).add(Buffer.from(o, "hex").reverse())) : p.add($.OP_FALSE).add($.OP_FALSE), Tt(a) && (R.validateArgument(lr(a, 0, 19), "decimals must be between 0 and 18"), p.add(a <= 16 ? mt.smallInt(a) : X.fromNumber(a).toScriptNumBuffer())), p;
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
  static buildTokenDescription(e, t, i, o, a) {
    return R.validateArgument(te(e) && lr(e.length, 2, 9), "Ticker must be 2-8 chars"), R.validateArgument(te(t) && lr(t.length, 2, 26), "Name must be 2-25 chars"), R.validateArgument(te(i) && !Kt(i), "Zip URL is missing"), R.validateArgument(te(o) && !Kt(o), "Zip hash is missing"), R.validateArgument(Tt(a) && lr(a, 0, 19), "Decimals must be a number 0-18"), new URL(i), ee.empty().add($.OP_RETURN).add(X.fromNumber(bi.NRC1).toScriptNumBuffer()).add(Buffer.from(e)).add(Buffer.from(t)).add(Buffer.from(i)).add(Buffer.from(o, "hex").reverse()).add(a <= 16 ? mt.smallInt(a) : X.fromNumber(a).toScriptNumBuffer());
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
  static buildNFTCollectionDescription(e, t, i, o) {
    return R.validateArgument(te(e) && lr(e.length, 2, 9), "Ticker must be 2-8 chars"), R.validateArgument(te(t) && lr(t.length, 2, 26), "Name must be 2-25 chars"), R.validateArgument(te(i) && !Kt(i), "Zip URL is missing"), R.validateArgument(te(o) && !Kt(o), "Zip hash is missing"), new URL(i), ee.empty().add($.OP_RETURN).add(X.fromNumber(bi.NRC2).toScriptNumBuffer()).add(Buffer.from(e)).add(Buffer.from(t)).add(Buffer.from(i)).add(Buffer.from(o, "hex").reverse()).add(mt.smallInt(0));
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
  static buildNFTDescription(e, t) {
    return R.validateArgument(te(e) && !Kt(e), "Zip URL is missing"), R.validateArgument(te(t) && !Kt(t), "Zip hash is missing"), new URL(e), ee.empty().add($.OP_RETURN).add(X.fromNumber(bi.NRC3).toScriptNumBuffer()).add(Buffer.from(e)).add(Buffer.from(t, "hex").reverse());
  }
}
var Co = /* @__PURE__ */ (function(r) {
  return r[r.ALL = 0] = "ALL", r[r.FIRSTN = 1] = "FIRSTN", r[r.THISIN = 2] = "THISIN", r[r.LAST_VALID = 2] = "LAST_VALID", r;
})({}), Fo = /* @__PURE__ */ (function(r) {
  return r[r.ALL = 0] = "ALL", r[r.FIRSTN = 1] = "FIRSTN", r[r.TWO = 2] = "TWO", r[r.LAST_VALID = 2] = "LAST_VALID", r;
})({});
class Vt {
  static {
    this.MAX_SIZE = 4;
  }
  constructor() {
    this.inType = 0, this.outType = 0, this.inData = [], this.outData = [];
  }
  /**
  * creates a sighash that is the most restrictive -- it signs all inputs and outputs
  */
  static get ALL() {
    return new Vt();
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
    return this.inType = 2, this.inData = [], this;
  }
  /**
  * Include only the n first inputs in the preimage sighash
  * 
  * @param n The first inputs to include
  */
  setFirstNIn(e) {
    return R.validateArgument(e >= 0 && e < 256, "n", "out of range (0-255)."), this.inType = 1, this.inData = [
      e
    ], this;
  }
  /**
  * Include only the n first outputs in the preimage sighash
  * 
  * @param n The first outputs to include
  */
  setFirstNOut(e) {
    return R.validateArgument(e >= 0 && e < 256, "n", "out of range (0-255)."), this.outType = 1, this.outData = [
      e
    ], this;
  }
  /**
  * Include specific 2 outputs in the preimage sighash
  * 
  * @param a The 1st output to include
  * @param b The 2nd output to include
  */
  set2Out(e, t) {
    return R.validateArgument(e >= 0 && e < 256, "a", "out of range (0-255)."), R.validateArgument(t >= 0 && t < 256, "b", "out of range (0-255)."), this.outType = 2, this.outData = [
      e,
      t
    ], this;
  }
  toBuffer() {
    if (this.hasAll()) return Buffer.alloc(0);
    let e = new Je(), t = this.inType << 4 | this.outType;
    switch (e.writeUInt8(t), this.inType) {
      case 1:
        R.validateState(this.inData.length > 0, "Missing input data"), e.writeUInt8(this.inData[0]);
        break;
      case 2:
      case 0:
        break;
      default:
        throw new Error("Malformed sighash type");
    }
    switch (this.outType) {
      case 2:
        R.validateState(this.outData.length > 1, "Missing output data"), e.writeUInt8(this.outData[0]), e.writeUInt8(this.outData[1]);
        break;
      case 1:
        R.validateState(this.outData.length > 0, "Missing output data"), e.writeUInt8(this.outData[0]);
        break;
      case 0:
        break;
      default:
        throw new Error("Malformed sighash type");
    }
    return e.toBuffer();
  }
  static fromBuffer(e) {
    if (R.validateArgument(W.isBuffer(e), "buf"), e.length == 0) return this.ALL;
    let t = new Vt(), i = new Ui(e), o = i.readUInt8();
    if (t.outType = o & 15, t.inType = o >> 4, t.isInvalid()) throw new Error("Invalid sighash buffer");
    const a = (p) => {
      if (p.finished()) throw new Error("Invalid sighash buffer");
      return p.readUInt8();
    };
    if (t.inType == 1 && t.inData.push(a(i)), t.outType == 1 ? t.outData.push(a(i)) : t.outType == 2 && (t.outData.push(a(i)), t.outData.push(a(i))), !i.finished()) throw new Error("Invalid sighash buffer");
    return t;
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
  static fromHex(e) {
    return typeof e == "string" && e.length === 0 ? this.ALL : (R.validateArgument(vt.isHexa(e), "Not a hex string"), this.fromBuffer(Buffer.from(e, "hex")));
  }
  /** 
  * Convert to a human readable representation of the sighash
  */
  toString() {
    if (this.hasAll()) return "ALL";
    let e = "";
    switch (this.inType) {
      case 0:
        e += "ALL_IN";
        break;
      case 2:
        e += "THIS_IN";
        break;
      case 1:
        e += `FIRST_${this.inData[0]}_IN`;
        break;
      default:
        return "INVALID";
    }
    switch (e += "|", this.outType) {
      case 0:
        e += "ALL_OUT";
        break;
      case 2:
        e += `${this.outData[0]}_${this.outData[1]}_OUT`;
        break;
      case 1:
        e += `FIRST_${this.outData[0]}_OUT`;
        break;
      default:
        return "INVALID";
    }
    return e;
  }
  /**
  * Create sighash from human readable represantation
  * @see toString 
  */
  static fromString(e) {
    if (R.validateArgument(te(e), "Not a string"), e == "ALL") return this.ALL;
    R.validateArgument(e.includes("|"), "Not a sighash string");
    let t = new Vt(), [i, o] = e.split("|");
    if (i == "THIS_IN") t.inType = 2;
    else if (i != "ALL_IN") {
      let a = i.match(/^FIRST_(\d+)_IN$/);
      R.validateState(!ze(a), "Not a sighash string"), t.setFirstNIn(parseInt(a[1]));
    }
    if (o != "ALL_OUT") {
      let a = o.match(/^FIRST_(\d+)_OUT$/), p = o.match(/^(\d+)_(\d+)_OUT$/);
      if (a) t.setFirstNOut(parseInt(a[1]));
      else if (p) t.set2Out(parseInt(p[1]), parseInt(p[2]));
      else throw new Error("Not a sighash string");
    }
    return t;
  }
}
class kt {
  constructor(e, t, i = 32768) {
    this.toJSON = this.toObject, this.type = i, this.value = e, this.scriptPubKey = t;
  }
  get value() {
    return this._value;
  }
  set value(e) {
    e = BigInt(e), R.validateArgument(vt.isNaturalBigInt(e), "Output value is not a natural bigint"), this._value = e;
  }
  get scriptPubKey() {
    return this._scriptPubKey;
  }
  set scriptPubKey(e) {
    if (oe(this._scriptPubKey) || (this.type = 32768), e instanceof ee) this._scriptPubKey = e;
    else if (te(e)) this._scriptPubKey = ee.fromString(e);
    else throw new TypeError("Invalid argument type: script");
    this.type == 32768 && (this.type = this._scriptPubKey.isPublicKeyTemplateOut() || this._scriptPubKey.isScriptTemplateOut() ? 1 : 0);
  }
  invalidValue() {
    return this.value > BigInt(Number.MAX_SAFE_INTEGER) ? "transaction txout value greater than max safe integer" : this.value < 0n ? "transaction txout negative" : !1;
  }
  toObject() {
    return {
      type: this.type,
      value: this.value.toString(),
      scriptPubKey: this.scriptPubKey.toHex()
    };
  }
  static fromObject(e) {
    return R.validateArgument(Oe(e), "data", "Unrecognized argument for Output"), new kt(e.value, e.scriptPubKey, e.type);
  }
  inspect() {
    return `<Output (type: ${this.type}) (${this.value.toString()} sats) ${this.scriptPubKey.inspect()}>`;
  }
  static fromBufferReader(e) {
    let t = e.readVarintNum(), i = e.readUInt64LEBN(), o = e.readVarintNum(), a = o !== 0 ? e.read(o) : Buffer.from([]);
    return new kt(i.toBigInt(), ee.fromBuffer(a), t);
  }
  toBufferWriter(e) {
    return e || (e = new Je()), e.writeUInt8(this.type), e.writeUInt64LEBN(X.fromBigInt(this.value)), e.writeVarLengthBuf(this.scriptPubKey.toBuffer()), e;
  }
}
class xt {
  static {
    this.SEQUENCE_FINAL = 4294967295;
  }
  constructor(e) {
    this.toJSON = this.toObject, e && this._set(e);
  }
  get scriptSig() {
    return this._scriptSig;
  }
  set scriptSig(e) {
    if (e instanceof ee) this._scriptSig = e;
    else if (te(e)) this._scriptSig = ee.fromString(e);
    else throw new TypeError("Invalid argument type: script");
  }
  _set(e) {
    if (this.type = 0, ze(e.scriptSig)) throw new TypeError("Need a script to create an input");
    this.scriptSig = e.scriptSig, this.outpoint = W.isBuffer(e.outpoint) ? e.outpoint : Buffer.from(e.outpoint, "hex"), this.amount = BigInt(e.amount), this.sequenceNumber = oe(e.sequenceNumber) ? xt.SEQUENCE_FINAL : e.sequenceNumber, e.output && (this.output = e.output instanceof kt ? e.output : kt.fromObject(e.output));
  }
  static fromObject(e) {
    return R.validateArgument(Oe(e), "obj"), new xt(e);
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
  static fromBufferReader(e) {
    let t = new xt();
    return t.type = e.readUInt8(), t.outpoint = e.readReverse(32), t.scriptSig = ee.fromBuffer(e.readVarLengthBuffer()), t.sequenceNumber = e.readUInt32LE(), t.amount = e.readUInt64LEBN().toBigInt(), t;
  }
  toBufferWriter(e, t = !0) {
    return e || (e = new Je()), e.writeUInt8(this.type), e.writeReverse(this.outpoint), t && e.writeVarLengthBuf(this.scriptSig.toBuffer()), e.writeUInt32LE(this.sequenceNumber), e.writeUInt64LEBN(X.fromBigInt(this.amount)), e;
  }
  estimateSize() {
    return this.toBufferWriter().toBuffer().length;
  }
  isFinal() {
    return this.sequenceNumber !== xt.SEQUENCE_FINAL;
  }
  clearSignatures() {
    return this.scriptSig = ee.empty(), this;
  }
  getSubscript() {
    throw Error("Abstract Method Invocation: Input#getSubscript");
  }
  /**
  * @returns true if the provided private key can sign this input
  */
  canSign(e) {
    throw Error("Abstract Method Invocation: Input#canSign");
  }
  isFullySigned() {
    throw Error("Abstract Method Invocation: Input#isFullySigned");
  }
  addSignature(e) {
    throw Error("Abstract Method Invocation: Input#addSignature");
  }
}
class ji extends xt {
  static {
    this.SCRIPT_SIZE = 99;
  }
  getSubscript() {
    return R.validateState(this.output instanceof kt, "missing associated output"), this.output.scriptPubKey;
  }
  canSign(e) {
    return this.output instanceof kt ? le.sha256ripemd160(e.publicKey.toBuffer()).equals(this.output.scriptPubKey.getPublicKeyHash()) : !1;
  }
  isFullySigned() {
    return this.scriptSig.isPublicKeyHashIn();
  }
  addSignature(e) {
    return this.scriptSig = Et.buildPublicKeyHashIn(e.publicKey, e.signature), this;
  }
  estimateSize() {
    return this.isFullySigned() ? super.estimateSize() : 34 + ji.SCRIPT_SIZE + 4 + 8;
  }
}
class Ki extends xt {
  static {
    this.SCRIPT_SIZE = 100;
  }
  getSubscript() {
    return ee.empty().add($.OP_FROMALTSTACK).add($.OP_CHECKSIGVERIFY);
  }
  canSign(e) {
    return this.output instanceof kt ? le.sha256ripemd160(ee.empty().add(e.publicKey.toBuffer()).toBuffer()).equals(this.output.scriptPubKey.getConstraintHash()) : !1;
  }
  isFullySigned() {
    return this.scriptSig.isPublicKeyTemplateIn();
  }
  addSignature(e) {
    let t = ee.empty().add(e.publicKey.toBuffer()), i = ee.empty().add(e.toTxSatisfier());
    return this.scriptSig = Et.buildScriptTemplateIn($.OP_1, t, i), this;
  }
  estimateSize() {
    return this.isFullySigned() ? super.estimateSize() : 34 + Ki.SCRIPT_SIZE + 4 + 8;
  }
}
class Lr extends xt {
  /**
  * Represents a special kind of input of generic ScriptTemplate kind.
  * 
  * WARNING: this is a general case where the signature is similar to p2pkt and added to scriptSig as push signature data.
  * If you have complex smart contract, consider extending this class (or Input class) and implement the necessary logic,
  * or sign it manually.
  */
  constructor(e) {
    R.validateArgument(Oe(e?.templateData), "Missing template object"), R.validateArgument(Oe(e?.output), "Missing associated utxo");
    let t = e.templateData;
    R.validateArgument(t.templateScript instanceof ee || te(t.templateScript), "Invalid template"), R.validateArgument(t.constraintScript instanceof ee || te(t.constraintScript) || t.constraintScript === $.OP_FALSE, "Invalid constraint"), R.validateArgument(oe(t.publicKey) || t.publicKey instanceof Ke || te(t.publicKey), "Invalid pubkey"), super(e), this.toJSON = this.toObject, this.templateScript = te(t.templateScript) ? ee.fromString(t.templateScript) : t.templateScript, this.constraintScript = te(t.constraintScript) ? ee.fromString(t.constraintScript) : t.constraintScript, this.publicKey = te(t.publicKey) ? Ke.fromString(t.publicKey) : t.publicKey;
    let i = this.output.scriptPubKey.getTemplateHash();
    R.validateState(W.isBuffer(i) && i.equals(le.sha256ripemd160(this.templateScript.toBuffer())), "Provided template doesn't match to the provided output");
    let o = this.output.scriptPubKey.getConstraintHash(), a = this.constraintScript instanceof ee && W.isBuffer(o) && o.equals(le.sha256ripemd160(this.constraintScript.toBuffer()));
    R.validateState(o === this.constraintScript || a, "Provided constraint doesn't match to the provided output");
  }
  toObject() {
    return {
      ...super.toObject(),
      templateData: {
        templateScript: this.templateScript.toHex(),
        constraintScript: this.constraintScript === $.OP_FALSE ? $.OP_FALSE : this.constraintScript.toHex(),
        publicKey: this.publicKey?.toString()
      }
    };
  }
  static fromObject(e) {
    return R.validateArgument(Oe(e), "obj"), new Lr(e);
  }
  getSubscript() {
    return this.templateScript;
  }
  canSign(e) {
    return this.publicKey?.toString() === e.publicKey.toString();
  }
  isFullySigned() {
    return this.scriptSig.isScriptTemplateIn() && this.templateScript.equals(ee.fromBuffer(this.scriptSig.chunks[0].buf)) && (!(this.constraintScript instanceof ee) || this.constraintScript.equals(ee.fromBuffer(this.scriptSig.chunks[1].buf)));
  }
  addSignature(e) {
    let t = ee.empty().add(e.toTxSatisfier());
    return this.scriptSig = Et.buildScriptTemplateIn(this.templateScript, this.constraintScript, t), this;
  }
  estimateSize() {
    if (this.isFullySigned()) return super.estimateSize();
    let e = this._estimateScriptSize();
    return 33 + (e < 253 ? 1 : 3) + e + 4 + 8;
  }
  _estimateScriptSize() {
    let e = ee.empty().add(this.templateScript.toBuffer());
    return this.constraintScript instanceof ee && e.add(this.constraintScript.toBuffer()), e.toBuffer().length + 1 + 64;
  }
}
class Le {
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
  constructor(e) {
    if (this.uncheckedSerialize = this.toString, this.toJSON = this.toObject, this.version = Le.CURRENT_VERSION, this.inputs = [], this.outputs = [], this.nLockTime = 0, e)
      if (W.isBuffer(e)) this.fromBuffer(e);
      else if (vt.isHexa(e)) this.fromString(e);
      else if (Oe(e)) this.fromObject(e);
      else throw new TypeError("Must provide an object or string to deserialize a transaction");
  }
  get id() {
    let e = new Je().write(this._getTxIdem()).write(this._getTxSatisfier()).toBuffer();
    return le.sha256sha256(e).reverse().toString("hex");
  }
  get idem() {
    return this._getTxIdem().reverse().toString("hex");
  }
  get outputAmount() {
    return this.outputs.reduce((e, t) => e + t.value, 0n);
  }
  get inputAmount() {
    return this.inputs.reduce((e, t) => e + t.amount, 0n);
  }
  _getTxIdem() {
    return le.sha256sha256(this._toIdemBuffer());
  }
  _getTxSatisfier() {
    return le.sha256sha256(this._toSatisfierBuffer());
  }
  /**
  * Create a 'shallow' copy of the transaction, by serializing and deserializing.
  * it dropping any additional information that inputs and outputs may have hold
  *
  * @param transaction
  */
  static shallowCopy(e) {
    return new Le(e.toBuffer());
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
  getSerializationError(e) {
    if (this._invalidAmount()) return new Error("Output satoshis are invalid");
    if (this.outputs.length > 256) return new Error("Too many outputs (> 256)");
    if (this.inputs.length > 256) return new Error("Too many inputs (> 256)");
    let t = this.getUnspentValue(), i;
    return t < 0 ? e?.disableMoreOutputThanInput || (i = new Error("Invalid outputs amount sum")) : i = this._hasFeeError(t), i || this._hasDustOutputs(e) || this._isMissingSignatures(e);
  }
  _invalidAmount() {
    return this.outputs.some((e) => e.invalidValue());
  }
  _hasDustOutputs(e) {
    return e?.disableDustOutputs ? void 0 : this.outputs.some((i) => i.value < Le.DUST_AMOUNT && !i.scriptPubKey.isDataOut()) ? new Error("Dust amount detected in one output") : void 0;
  }
  _hasFeeError(e) {
    if (!oe(this._fee) && BigInt(this._fee) !== e) return new Error(`Unspent value is ${e} but specified fee is ${this._fee}`);
  }
  _estimateFee() {
    let e = this._estimateSize(), t = this.getUnspentValue(), i = this._feePerByte || Le.FEE_PER_BYTE;
    const o = (p) => p * i;
    let a = Math.ceil(o(e) + o(this._estimateSizeOfChangeOutput()));
    return !this._changeScript || t <= a || t - BigInt(a) < Le.DUST_AMOUNT ? Number(t) : a;
  }
  _estimateSizeOfChangeOutput() {
    if (!this._changeScript) return 0;
    let e = this._changeScript.toBuffer().length;
    return 9 + Je.varintBufNum(e).length + e;
  }
  _estimateSize() {
    let e = 5;
    return e += this.inputs.length < 253 ? 1 : 3, this.inputs.forEach((t) => {
      e += t.estimateSize();
    }), e += this.outputs.length < 253 ? 1 : 3, this.outputs.forEach((t) => {
      e += t.toBufferWriter().toBuffer().length;
    }), e;
  }
  _isMissingSignatures(e) {
    if (!e?.disableIsFullySigned && !this.isFullySigned())
      return new Error("Some inputs have not been fully signed");
  }
  isFullySigned() {
    if (this.inputs.some((e) => e.isFullySigned === xt.prototype.isFullySigned)) throw new Error("Unable to verify signature: Unrecognized script kind, or not enough information to execute script. This usually happens when creating a transaction from a serialized transaction");
    return this.inputs.every((e) => e.isFullySigned());
  }
  /**
  * @returns true if the transaction has enough info on all inputs to be correctly validated
  */
  hasAllUtxoInfo() {
    return this.inputs.every((e) => !oe(e.output));
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
    return this.isCoinbase() ? 0 : oe(this._fee) ? this._changeScript ? this._estimateFee() : Number(this.getUnspentValue()) : this._fee;
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
    return (this._feePerByte || Le.FEE_PER_BYTE) * this._estimateSize();
  }
  clearSignatures() {
    this.inputs.forEach((e) => e.clearSignatures());
  }
  /**
  * Retrieve a hexa string that can be used with nexad's CLI interface
  * (decoderawtransaction, sendrawtransaction)
  *
  * @param opts allows to skip certain tests.
  */
  checkedSerialize(e) {
    let t = this.getSerializationError(e);
    if (t) throw t;
    return this.toString();
  }
  toString() {
    return this.toBuffer().toString("hex");
  }
  inspect() {
    return `<Transaction: ${this}>`;
  }
  fromString(e) {
    return this.fromBuffer(Buffer.from(e, "hex"));
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
  serialize(e) {
    return e === !0 || Oe(e) && e.disableAll ? this.uncheckedSerialize() : this.checkedSerialize(Oe(e) ? e : void 0);
  }
  /**
  * Manually set the fee for this transaction. Beware that this resets all the signatures
  * for inputs.
  *
  * @param amount satoshis to be set as fees
  * @return this, for chaining
  */
  setFee(e) {
    return R.validateArgument(Tt(e), "amount must be a number"), this._fee = e, this._updateChangeOutput(), this;
  }
  /**
  * Manually set the fee per Byte for this transaction. Beware that this resets all the signatures
  * for inputs.
  * fee per Byte will be ignored if fee property was set manually
  *
  * @param amount satoshis per Byte to be used as fee rate
  * @return this, for chaining
  */
  setFeePerByte(e) {
    return R.validateArgument(Tt(e), "amount must be a number"), this._feePerByte = e, this._updateChangeOutput(), this;
  }
  /**
  * Add an output to the transaction.
  *
  * @param output the output to add.
  * @return this, for chaining
  */
  addOutput(e) {
    return R.validateArgumentType(e, kt, "output"), this.outputs.push(e), this._updateChangeOutput(), this;
  }
  removeOutput(e) {
    return this._removeOutput(e), this._updateChangeOutput(), this;
  }
  _removeOutput(e) {
    this.outputs = this.outputs.filter((t, i) => i !== e);
  }
  /**
  * Remove all outputs from the transaction.
  *
  * @return this, for chaining
  */
  clearOutputs() {
    return this.outputs = [], this.clearSignatures(), this._updateChangeOutput(), this;
  }
  updateOutputAmount(e, t) {
    this.outputs[e].value = BigInt(t), this._updateChangeOutput();
  }
  /**
  * Set the change address for this transaction
  *
  * Beware that this resets all the signatures for inputs.
  *
  * @param address An address for change to be sent to.
  * @return this, for chaining
  */
  setChangeOutput(e) {
    return R.validateArgument(!ze(e), "address is required."), this._changeScript = Et.buildOutFromAddress(e), this._updateChangeOutput(), this;
  }
  /**
  * @returns change output, if it exists
  */
  getChangeOutput() {
    if (!oe(this._changeIndex)) return this.outputs[this._changeIndex];
  }
  _updateChangeOutput() {
    if (!this._changeScript) return;
    this.clearSignatures(), oe(this._changeIndex) || this._removeOutput(this._changeIndex);
    let e = this.getUnspentValue(), t = this.getFee(), i = e - BigInt(t);
    i >= Le.DUST_AMOUNT ? (this._changeIndex = this.outputs.length, this.outputs.push(new kt(i, this._changeScript))) : this._changeIndex = void 0;
  }
  /**
  * Add an input to this transaction, without checking that the input has information about
  * the output that it's spending.
  *
  * @param input the input to add
  * @return this, for chaining
  */
  uncheckedAddInput(e) {
    return R.validateArgumentType(e, xt, "input"), this.inputs.push(e), this._updateChangeOutput(), this;
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
  addInput(e, t, i) {
    if (R.validateArgumentType(e, xt, "input"), oe(e.output) && (oe(t) || oe(i))) throw new Error("Need information about the UTXO script and amount");
    if (oe(e.output) && !oe(t) && !oe(i)) {
      let o = t instanceof ee ? t : new ee(t);
      e.output = new kt(BigInt(i), o);
    }
    return this.uncheckedAddInput(e);
  }
  removeInput(e) {
    return this.inputs = this.inputs.filter((t) => t.outpoint.toString("hex") != e), this._updateChangeOutput(), this;
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
  setLockTime(e) {
    return R.validateArgument(Tt(e), "locktime", "must be a number"), this.inputs.forEach((t) => {
      t.sequenceNumber === xt.SEQUENCE_FINAL && (t.sequenceNumber = xt.SEQUENCE_FINAL - 1);
    }), this.nLockTime = e, this;
  }
  /**
  *  Returns a semantic version of the transaction's nLockTime.
  *  If nLockTime is 0, it returns null,
  *  if it is < 500000000, it returns a block height (number)
  *  else it returns a Date object.
  */
  getLockTime() {
    return this.nLockTime ? this.nLockTime < Le.NLOCKTIME_BLOCKHEIGHT_LIMIT ? this.nLockTime : new Date(1e3 * this.nLockTime) : null;
  }
  toBuffer() {
    return this.toBufferWriter().toBuffer();
  }
  toBufferWriter(e, t = !0) {
    return e || (e = new Je()), e.writeUInt8(this.version), e.writeVarintNum(this.inputs.length), this.inputs.forEach((i) => i.toBufferWriter(e, t)), e.writeVarintNum(this.outputs.length), this.outputs.forEach((i) => i.toBufferWriter(e)), e.writeUInt32LE(this.nLockTime), e;
  }
  _toIdemBuffer() {
    let e = new Je();
    return this.toBufferWriter(e, !1).toBuffer();
  }
  _toSatisfierBuffer() {
    let e = new Je();
    return e.writeInt32LE(this.inputs.length), this.inputs.forEach((t) => {
      e.write(t.scriptSig.toBuffer()), e.writeUInt8($.OP_INVALIDOPCODE);
    }), e.toBuffer();
  }
  fromBuffer(e) {
    let t = new Ui(e);
    return this.fromBufferReader(t);
  }
  fromBufferReader(e) {
    R.validateState(!e.finished(), "No transaction data received"), this.version = e.readUInt8();
    let t = e.readVarintNum();
    for (let o = 0; o < t; o++) this.inputs.push(xt.fromBufferReader(e));
    let i = e.readVarintNum();
    for (let o = 0; o < i; o++) this.outputs.push(kt.fromBufferReader(e));
    return this.nLockTime = e.readUInt32LE(), this;
  }
  toObject() {
    let e = {
      id: this.id,
      idem: this.idem,
      version: this.version,
      inputs: this.inputs.map((t) => t.toObject()),
      outputs: this.outputs.map((t) => t.toObject()),
      nLockTime: this.nLockTime
    };
    return oe(this._changeScript) || (e.changeScript = this._changeScript.toHex()), oe(this._changeIndex) || (e.changeIndex = this._changeIndex), oe(this._fee) || (e.fee = this._fee), oe(this._feePerByte) || (e.feePerByte = this._feePerByte), e;
  }
  fromObject(e) {
    R.validateArgument(Oe(e), "transaction"), e instanceof Le && (e = e.toObject()), this.nLockTime = e.nLockTime, this.version = e.version;
    for (let t of e.inputs) {
      if (oe(t.output?.scriptPubKey)) {
        this.uncheckedAddInput(new xt(t));
        continue;
      }
      let i = new ee(t.output.scriptPubKey), o;
      if (i.isPublicKeyHashOut()) o = new ji(t);
      else if (i.isPublicKeyTemplateOut()) o = new Ki(t);
      else if (i.isScriptTemplateOut())
        "templateData" in t ? o = new Lr(t) : o = new xt(t);
      else throw new Error(`Unsupported input script type: ${i}`);
      this.addInput(o);
    }
    for (let t of e.outputs) this.addOutput(kt.fromObject(t));
    return oe(e.changeIndex) || (this._changeIndex = e.changeIndex), oe(e.changeScript) || (this._changeScript = new ee(e.changeScript)), oe(e.fee) || (this._fee = e.fee), oe(e.feePerByte) || (this._feePerByte = e.feePerByte), this._checkConsistency(e), this;
  }
  _checkConsistency(e) {
    oe(this._changeIndex) || (R.validateState(!oe(this._changeScript), "Change script is expected."), R.validateState(!oe(this.outputs[this._changeIndex]), "Change index points to undefined output."), R.validateState(this.outputs[this._changeIndex].scriptPubKey.toHex() === this._changeScript?.toHex(), "Change output has an unexpected script.")), e?.id && R.validateState(e.id === this.id, "Id in object does not match transaction id.");
  }
}
class cn {
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
  constructor(e) {
    this.toJSON = this.toObject, R.validateArgument(Oe(e), "Must provide an object from where to extract data"), R.validateArgument(vt.isHexa(e.outpoint), "Invalid outpoint hash"), R.validateArgument(!oe(e.satoshis) || !oe(e.amount), "Must provide satoshis or amount"), R.validateArgument(!oe(e.scriptPubKey) || !oe(e.address), "Must provide script or address"), this.outpoint = e.outpoint, this.satoshis = oe(e.satoshis) ? zi.parseNEXA(e.amount.toString()) : BigInt(e.satoshis), this.scriptPubKey = oe(e.scriptPubKey) ? Et.buildOutFromAddress(e.address, e.groupId, e.groupAmount) : new ee(e.scriptPubKey);
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
  static fromObject(e) {
    return new cn(e);
  }
  /**
  * Returns a plain object (no prototype or methods) with the associated info for this utxo
  */
  toObject() {
    return {
      outpoint: this.outpoint,
      scriptPubKey: this.scriptPubKey.toHex(),
      amount: zi.formatNEXA(this.satoshis)
    };
  }
}
class oi {
  /**
  * Wrapper around Signature with fields related to signing a transaction specifically
  */
  constructor(e) {
    this.toJSON = this.toObject, oi._validateArgs(e), this.inputIndex = e.inputIndex, this.publicKey = te(e.publicKey) ? Ke.fromString(e.publicKey) : e.publicKey, this.subscript = te(e.subscript) ? ee.fromHex(e.subscript) : e.subscript, this.signature = te(e.signature) ? Nt.fromString(e.signature) : e.signature, this.sigType = te(e.sigType) ? Vt.fromString(e.sigType) : e.sigType;
  }
  static _validateArgs(e) {
    R.validateArgument(Oe(e), "TxSignature must be instantiated from an object"), R.validateArgument(!ze(e.publicKey) && !!Ke.from(e.publicKey), "publicKey"), R.validateArgument(!ze(e.inputIndex), "inputIndex"), R.validateState(Tt(e.inputIndex), "inputIndex must be a number"), R.validateArgument(!ze(e.subscript), "subscript"), R.validateState(e.subscript instanceof ee || vt.isHexa(e.subscript), "subscript must be an object or hexa value"), R.validateArgument(!ze(e.signature), "signature"), R.validateState(e.signature instanceof Nt || vt.isHexa(e.signature), "signature must be an object or hexa value"), R.validateState(e.sigType instanceof Vt || te(e.sigType), "sigtype must be a sigtype object or string");
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
  static fromObject(e) {
    return new oi(e);
  }
  toTxSatisfier() {
    return this.signature.toTxFormat(this.sigType.toBuffer());
  }
}
class qa {
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
  static sign(e, t, i, o, a) {
    let p = this.buildSighash(e, t, i, o);
    return $t.sign(p, a, "little");
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
  static verify(e, t, i, o, a, p) {
    R.validateArgument(!oe(e), "transaction"), R.validateArgument(!oe(i), "signature"), R.validateArgument(!oe(o), "sighashType");
    let c = this.buildSighash(e, t, o, a);
    return $t.verify(c, i, p, "little");
  }
  /**
  * Returns a buffer of length 32 bytes with the hash that needs to be signed for OP_CHECKSIG(VERIFY).
  *
  * @param transaction the transaction to sign
  * @param inputNumber the input index for the signature
  * @param sighashType the sighash type
  * @param subscript the script that will be signed
  */
  static buildSighash(e, t, i, o) {
    let a = this._getSighashComponents(e, t, i), p = new Je();
    p.writeUInt8(e.version), p.write(a.hashPrevouts), p.write(a.hashInputAmounts), p.write(a.hashSequence), p.writeVarLengthBuf(o.toBuffer()), p.write(a.hashOutputs), p.writeUInt32LE(e.nLockTime), p.writeVarLengthBuf(i.toBuffer());
    let c = p.toBuffer();
    return le.sha256sha256(c).reverse();
  }
  static _getSighashComponents(e, t, i) {
    R.validateArgument(!i.isInvalid(), "sighashType");
    let o, a, p, c;
    switch (i.inType) {
      case Co.FIRSTN:
        let g = i.inData[0];
        R.validateArgument(g <= e.inputs.length, "firstN out of range"), o = this._getPrevoutHash(e, g), a = this._getSequenceHash(e, g), p = this._getInputAmountHash(e, g);
        break;
      case Co.THISIN:
        R.validateArgument(t < e.inputs.length, "inputNumber out of range"), o = this._getPrevoutHashOf(e, t), a = this._getSequenceHashOf(e, t), p = this._getInputAmountHashOf(e, t);
        break;
      default:
        o = this._getPrevoutHash(e, e.inputs.length), a = this._getSequenceHash(e, e.inputs.length), p = this._getInputAmountHash(e, e.inputs.length);
        break;
    }
    switch (i.outType) {
      case Fo.FIRSTN:
        let g = i.outData[0];
        R.validateArgument(g <= e.outputs.length, "firstN out of range"), c = this._getOutputsHash(e, g);
        break;
      case Fo.TWO:
        let [h, m] = i.outData;
        R.validateArgument(h < e.outputs.length, "out1 out of range"), R.validateArgument(m < e.outputs.length, "out2 out of range"), c = this._getOutputsHashOf(e, h, m);
        break;
      default:
        c = this._getOutputsHash(e, e.outputs.length);
        break;
    }
    return {
      hashPrevouts: o,
      hashSequence: a,
      hashInputAmounts: p,
      hashOutputs: c
    };
  }
  static _getPrevoutHash(e, t) {
    let i = new Je();
    for (let a = 0; a < t; a++)
      i.writeUInt8(e.inputs[a].type), i.writeReverse(e.inputs[a].outpoint);
    let o = i.toBuffer();
    return le.sha256sha256(o);
  }
  static _getPrevoutHashOf(e, t) {
    let i = new Je();
    i.writeUInt8(e.inputs[t].type), i.writeReverse(e.inputs[t].outpoint);
    let o = i.toBuffer();
    return le.sha256sha256(o);
  }
  static _getSequenceHash(e, t) {
    let i = new Je();
    for (let a = 0; a < t; a++) i.writeUInt32LE(e.inputs[a].sequenceNumber);
    let o = i.toBuffer();
    return le.sha256sha256(o);
  }
  static _getSequenceHashOf(e, t) {
    let i = new Je();
    i.writeUInt32LE(e.inputs[t].sequenceNumber);
    let o = i.toBuffer();
    return le.sha256sha256(o);
  }
  static _getInputAmountHash(e, t) {
    let i = new Je();
    for (let a = 0; a < t; a++) i.writeUInt64LEBN(X.fromBigInt(e.inputs[a].amount));
    let o = i.toBuffer();
    return le.sha256sha256(o);
  }
  static _getInputAmountHashOf(e, t) {
    let i = new Je();
    i.writeUInt64LEBN(X.fromBigInt(e.inputs[t].amount));
    let o = i.toBuffer();
    return le.sha256sha256(o);
  }
  static _getOutputsHash(e, t) {
    let i = new Je();
    for (let a = 0; a < t; a++) e.outputs[a].toBufferWriter(i);
    let o = i.toBuffer();
    return le.sha256sha256(o);
  }
  static _getOutputsHashOf(e, t, i) {
    let o = new Je();
    e.outputs[t].toBufferWriter(o), e.outputs[i].toBufferWriter(o);
    let a = o.toBuffer();
    return le.sha256sha256(a);
  }
}
class Jr {
  constructor(e) {
    e instanceof Le ? this.transaction = e : this.transaction = new Le(e);
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
  from(e) {
    return rr(e) ? (e.forEach((i) => this.from(i)), this) : this.transaction.inputs.some((i) => i.outpoint.toString("hex") === e.outpoint) ? this : this._fromUtxo(new cn(e), e.templateData);
  }
  _fromUtxo(e, t) {
    let i;
    e.scriptPubKey.isPublicKeyHashOut() ? i = ji : e.scriptPubKey.isPublicKeyTemplateOut() ? i = Ki : e.scriptPubKey.isScriptTemplateOut() && Oe(t) ? i = Lr : i = xt;
    let o = new i({
      output: new kt(e.satoshis, e.scriptPubKey),
      outpoint: e.outpoint,
      scriptSig: ee.empty(),
      amount: e.satoshis,
      templateData: t
    });
    return this.transaction.addInput(o), this;
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
  to(e, t, i, o) {
    let a = Et.buildOutFromAddress(e, i, o), p = new kt(t, a);
    return this.transaction.addOutput(p), this;
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
  addData(e, t = !1) {
    let i = t ? new ee(e) : Et.buildDataOut(e), o = new kt(0, i);
    return this.transaction.addOutput(o), this;
  }
  /**
  * Set the change address for this transaction
  *
  * Beware that this resets all the signatures for inputs.
  *
  * @param address An address for change to be sent to.
  * @returns this, for chaining
  */
  change(e) {
    return this.transaction.setChangeOutput(e), this;
  }
  /**
  * Manually set the fee for this transaction. 
  * 
  * Beware that this resets all the signatures for inputs.
  *
  * @param amount satoshis to be used as fee
  * @returns this, for chaining
  */
  fee(e) {
    return this.transaction.setFee(e), this;
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
  feePerByte(e) {
    return this.transaction.setFeePerByte(e), this;
  }
  /**
  * Sets nLockTime so that transaction is not valid until the desired date
  * 
  * (a timestamp in seconds since UNIX epoch is also accepted)
  *
  * @param datetime Date object or unix timestamp number
  * @returns this, for chaining
  */
  lockUntilDate(e) {
    if (R.validateArgument(!oe(e), "datetime"), Tt(e) && e < Le.NLOCKTIME_BLOCKHEIGHT_LIMIT) throw new Error("Lock Time can't be earlier than UNIX date 500 000 000");
    return Vf(e) && (e = e.getTime() / 1e3), this.transaction.setLockTime(e), this;
  }
  /**
  * Sets nLockTime so that transaction is not valid until the desired block height.
  *
  * @param height the block height
  * @returns this, for chaining
  */
  lockUntilBlockHeight(e) {
    if (e >= Le.NLOCKTIME_BLOCKHEIGHT_LIMIT) throw new Error("Block Height can be at most 2^32 - 1");
    if (e < 0) throw new Error("Block Height cannot be negative");
    return this.transaction.setLockTime(e), this;
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
  sign(e) {
    return R.validateState(this.transaction.hasAllUtxoInfo(), "Not all utxo information is available to sign the transaction."), rr(e) ? (e.forEach((t) => this.sign(t)), this) : (this._getSignatures(e, Vt.ALL).forEach((t) => this._applySignature(t)), this);
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
  signInput(e, t, i) {
    te(e) && (e = this.transaction.inputs.findIndex((a) => a.outpoint.toString("hex") === e)), R.validateArgument(e >= 0 && e < this.transaction.inputs.length, "input", "out of range."), R.validateState(this.transaction.inputs[e].canSign(t), "The provided key cannot sign this input");
    let o = this._getSignature(e, t, i);
    return this._applySignature(o), this;
  }
  _getSignatures(e, t) {
    R.validateArgument(e instanceof gt, "privKey", "not a private key");
    let i = [];
    for (let o = 0; o < this.transaction.inputs.length; o++) {
      if (!this.transaction.inputs[o].canSign(e)) continue;
      let a = this._getSignature(o, e, t);
      i.push(a);
    }
    return i;
  }
  _getSignature(e, t, i) {
    let o = this.transaction.inputs[e].getSubscript();
    return new oi({
      inputIndex: e,
      publicKey: t.publicKey,
      subscript: o,
      signature: qa.sign(this.transaction, e, i, o, t),
      sigType: i
    });
  }
  _applySignature(e) {
    let t = qa.verify(this.transaction, e.inputIndex, e.signature, e.sigType, e.subscript, e.publicKey);
    R.validateState(t, "Signature is invalid"), this.transaction.inputs[e.inputIndex].addSignature(e);
  }
}
function Uc(r) {
  if (r !== void 0) {
    let e = "More than one instance of libnexa found. Please make sure to require libnexa and check that submodules do not also include their own libnexa dependency.";
    throw new Error(e);
  }
}
Uc(Is._libnexa_ver);
Is._libnexa_ver = `v${un.version}`;
const Rt = li.getInstance();
`${un.version}`, li.getInstance();
var Lt = {};
const qr = typeof globalThis == "object" && "crypto" in globalThis ? globalThis.crypto : void 0;
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function Ts(r) {
  return r instanceof Uint8Array || ArrayBuffer.isView(r) && r.constructor.name === "Uint8Array";
}
function Yr(r) {
  if (!Number.isSafeInteger(r) || r < 0)
    throw new Error("positive integer expected, got " + r);
}
function br(r, ...e) {
  if (!Ts(r))
    throw new Error("Uint8Array expected");
  if (e.length > 0 && !e.includes(r.length))
    throw new Error("Uint8Array expected of length " + e + ", got length=" + r.length);
}
function ln(r) {
  if (typeof r != "function" || typeof r.create != "function")
    throw new Error("Hash should be wrapped by utils.createHasher");
  Yr(r.outputLen), Yr(r.blockLen);
}
function si(r, e = !0) {
  if (r.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (e && r.finished)
    throw new Error("Hash#digest() has already been called");
}
function zs(r, e) {
  br(r);
  const t = e.outputLen;
  if (r.length < t)
    throw new Error("digestInto() expects output buffer of length at least " + t);
}
function jc(r) {
  return new Uint8Array(r.buffer, r.byteOffset, r.byteLength);
}
function Kc(r) {
  return new Uint32Array(r.buffer, r.byteOffset, Math.floor(r.byteLength / 4));
}
function mr(...r) {
  for (let e = 0; e < r.length; e++)
    r[e].fill(0);
}
function Xr(r) {
  return new DataView(r.buffer, r.byteOffset, r.byteLength);
}
function Ht(r, e) {
  return r << 32 - e | r >>> e;
}
function qc(r, e) {
  return r << e | r >>> 32 - e >>> 0;
}
const hn = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
function dn(r) {
  return r << 24 & 4278190080 | r << 8 & 16711680 | r >>> 8 & 65280 | r >>> 24 & 255;
}
const Os = hn ? (r) => r : (r) => dn(r), Dc = Os;
function Ns(r) {
  for (let e = 0; e < r.length; e++)
    r[e] = dn(r[e]);
  return r;
}
const Hc = hn ? (r) => r : Ns, Cs = /* @ts-ignore */ typeof Uint8Array.from([]).toHex == "function" && typeof Uint8Array.fromHex == "function", Vc = /* @__PURE__ */ Array.from({ length: 256 }, (r, e) => e.toString(16).padStart(2, "0"));
function Gc(r) {
  if (br(r), Cs)
    return r.toHex();
  let e = "";
  for (let t = 0; t < r.length; t++)
    e += Vc[r[t]];
  return e;
}
const Zt = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function Ro(r) {
  if (r >= Zt._0 && r <= Zt._9)
    return r - Zt._0;
  if (r >= Zt.A && r <= Zt.F)
    return r - (Zt.A - 10);
  if (r >= Zt.a && r <= Zt.f)
    return r - (Zt.a - 10);
}
function Wc(r) {
  if (typeof r != "string")
    throw new Error("hex string expected, got " + typeof r);
  if (Cs)
    return Uint8Array.fromHex(r);
  const e = r.length, t = e / 2;
  if (e % 2)
    throw new Error("hex string expected, got unpadded hex of length " + e);
  const i = new Uint8Array(t);
  for (let o = 0, a = 0; o < t; o++, a += 2) {
    const p = Ro(r.charCodeAt(a)), c = Ro(r.charCodeAt(a + 1));
    if (p === void 0 || c === void 0) {
      const g = r[a] + r[a + 1];
      throw new Error('hex string expected, got non-hex character "' + g + '" at index ' + a);
    }
    i[o] = p * 16 + c;
  }
  return i;
}
const Fs = async () => {
};
async function Rs(r, e, t) {
  let i = Date.now();
  for (let o = 0; o < r; o++) {
    t(o);
    const a = Date.now() - i;
    a >= 0 && a < e || (await Fs(), i += a);
  }
}
function pn(r) {
  if (typeof r != "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(r));
}
function Jc(r) {
  return new TextDecoder().decode(r);
}
function $r(r) {
  return typeof r == "string" && (r = pn(r)), br(r), r;
}
function Da(r) {
  return typeof r == "string" && (r = pn(r)), br(r), r;
}
function Yc(...r) {
  let e = 0;
  for (let i = 0; i < r.length; i++) {
    const o = r[i];
    br(o), e += o.length;
  }
  const t = new Uint8Array(e);
  for (let i = 0, o = 0; i < r.length; i++) {
    const a = r[i];
    t.set(a, o), o += a.length;
  }
  return t;
}
function Ls(r, e) {
  if (e !== void 0 && {}.toString.call(e) !== "[object Object]")
    throw new Error("options should be object or undefined");
  return Object.assign(r, e);
}
class mn {
}
function vr(r) {
  const e = (i) => r().update($r(i)).digest(), t = r();
  return e.outputLen = t.outputLen, e.blockLen = t.blockLen, e.create = () => r(), e;
}
function Us(r) {
  const e = (i, o) => r(o).update($r(i)).digest(), t = r({});
  return e.outputLen = t.outputLen, e.blockLen = t.blockLen, e.create = (i) => r(i), e;
}
function js(r) {
  const e = (i, o) => r(o).update($r(i)).digest(), t = r({});
  return e.outputLen = t.outputLen, e.blockLen = t.blockLen, e.create = (i) => r(i), e;
}
const Xc = vr, Zc = Us, Qc = js;
function $c(r = 32) {
  if (qr && typeof qr.getRandomValues == "function")
    return qr.getRandomValues(new Uint8Array(r));
  if (qr && typeof qr.randomBytes == "function")
    return Uint8Array.from(qr.randomBytes(r));
  throw new Error("crypto.getRandomValues must be defined");
}
const el = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  Hash: mn,
  abytes: br,
  aexists: si,
  ahash: ln,
  anumber: Yr,
  aoutput: zs,
  asyncLoop: Rs,
  byteSwap: dn,
  byteSwap32: Ns,
  byteSwapIfBE: Dc,
  bytesToHex: Gc,
  bytesToUtf8: Jc,
  checkOpts: Ls,
  clean: mr,
  concatBytes: Yc,
  createHasher: vr,
  createOptHasher: Us,
  createView: Xr,
  createXOFer: js,
  hexToBytes: Wc,
  isBytes: Ts,
  isLE: hn,
  kdfInputToBytes: Da,
  nextTick: Fs,
  randomBytes: $c,
  rotl: qc,
  rotr: Ht,
  swap32IfBE: Hc,
  swap8IfBE: Os,
  toBytes: $r,
  u32: Kc,
  u8: jc,
  utf8ToBytes: pn,
  wrapConstructor: Xc,
  wrapConstructorWithOpts: Zc,
  wrapXOFConstructorWithOpts: Qc
}, Symbol.toStringTag, { value: "Module" }));
function tl(r, e, t, i) {
  if (typeof r.setBigUint64 == "function")
    return r.setBigUint64(e, t, i);
  const o = BigInt(32), a = BigInt(4294967295), p = Number(t >> o & a), c = Number(t & a), g = i ? 4 : 0, h = i ? 0 : 4;
  r.setUint32(e + g, p, i), r.setUint32(e + h, c, i);
}
function rl(r, e, t) {
  return r & e ^ ~r & t;
}
function il(r, e, t) {
  return r & e ^ r & t ^ e & t;
}
class Ks extends mn {
  constructor(e, t, i, o) {
    super(), this.finished = !1, this.length = 0, this.pos = 0, this.destroyed = !1, this.blockLen = e, this.outputLen = t, this.padOffset = i, this.isLE = o, this.buffer = new Uint8Array(e), this.view = Xr(this.buffer);
  }
  update(e) {
    si(this), e = $r(e), br(e);
    const { view: t, buffer: i, blockLen: o } = this, a = e.length;
    for (let p = 0; p < a; ) {
      const c = Math.min(o - this.pos, a - p);
      if (c === o) {
        const g = Xr(e);
        for (; o <= a - p; p += o)
          this.process(g, p);
        continue;
      }
      i.set(e.subarray(p, p + c), this.pos), this.pos += c, p += c, this.pos === o && (this.process(t, 0), this.pos = 0);
    }
    return this.length += e.length, this.roundClean(), this;
  }
  digestInto(e) {
    si(this), zs(e, this), this.finished = !0;
    const { buffer: t, view: i, blockLen: o, isLE: a } = this;
    let { pos: p } = this;
    t[p++] = 128, mr(this.buffer.subarray(p)), this.padOffset > o - p && (this.process(i, 0), p = 0);
    for (let S = p; S < o; S++)
      t[S] = 0;
    tl(i, o - 8, BigInt(this.length * 8), a), this.process(i, 0);
    const c = Xr(e), g = this.outputLen;
    if (g % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const h = g / 4, m = this.get();
    if (h > m.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let S = 0; S < h; S++)
      c.setUint32(4 * S, m[S], a);
  }
  digest() {
    const { buffer: e, outputLen: t } = this;
    this.digestInto(e);
    const i = e.slice(0, t);
    return this.destroy(), i;
  }
  _cloneInto(e) {
    e || (e = new this.constructor()), e.set(...this.get());
    const { blockLen: t, buffer: i, length: o, finished: a, destroyed: p, pos: c } = this;
    return e.destroyed = p, e.finished = a, e.length = o, e.pos = c, o % t && e.buffer.set(i), e;
  }
  clone() {
    return this._cloneInto();
  }
}
const or = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]), sr = /* @__PURE__ */ Uint32Array.from([
  3238371032,
  914150663,
  812702999,
  4144912697,
  4290775857,
  1750603025,
  1694076839,
  3204075428
]), St = /* @__PURE__ */ Uint32Array.from([
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
]), At = /* @__PURE__ */ Uint32Array.from([
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
]), vi = /* @__PURE__ */ BigInt(2 ** 32 - 1), Lo = /* @__PURE__ */ BigInt(32);
function al(r, e = !1) {
  return e ? { h: Number(r & vi), l: Number(r >> Lo & vi) } : { h: Number(r >> Lo & vi) | 0, l: Number(r & vi) | 0 };
}
function nl(r, e = !1) {
  const t = r.length;
  let i = new Uint32Array(t), o = new Uint32Array(t);
  for (let a = 0; a < t; a++) {
    const { h: p, l: c } = al(r[a], e);
    [i[a], o[a]] = [p, c];
  }
  return [i, o];
}
const Uo = (r, e, t) => r >>> t, jo = (r, e, t) => r << 32 - t | e >>> t, Dr = (r, e, t) => r >>> t | e << 32 - t, Hr = (r, e, t) => r << 32 - t | e >>> t, gi = (r, e, t) => r << 64 - t | e >>> t - 32, yi = (r, e, t) => r >>> t - 32 | e << 64 - t;
function Qt(r, e, t, i) {
  const o = (e >>> 0) + (i >>> 0);
  return { h: r + t + (o / 2 ** 32 | 0) | 0, l: o | 0 };
}
const ol = (r, e, t) => (r >>> 0) + (e >>> 0) + (t >>> 0), sl = (r, e, t, i) => e + t + i + (r / 2 ** 32 | 0) | 0, ul = (r, e, t, i) => (r >>> 0) + (e >>> 0) + (t >>> 0) + (i >>> 0), fl = (r, e, t, i, o) => e + t + i + o + (r / 2 ** 32 | 0) | 0, cl = (r, e, t, i, o) => (r >>> 0) + (e >>> 0) + (t >>> 0) + (i >>> 0) + (o >>> 0), ll = (r, e, t, i, o, a) => e + t + i + o + a + (r / 2 ** 32 | 0) | 0, hl = /* @__PURE__ */ Uint32Array.from([
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
]), ur = /* @__PURE__ */ new Uint32Array(64);
let bn = class extends Ks {
  constructor(e = 32) {
    super(64, e, 8, !1), this.A = or[0] | 0, this.B = or[1] | 0, this.C = or[2] | 0, this.D = or[3] | 0, this.E = or[4] | 0, this.F = or[5] | 0, this.G = or[6] | 0, this.H = or[7] | 0;
  }
  get() {
    const { A: e, B: t, C: i, D: o, E: a, F: p, G: c, H: g } = this;
    return [e, t, i, o, a, p, c, g];
  }
  // prettier-ignore
  set(e, t, i, o, a, p, c, g) {
    this.A = e | 0, this.B = t | 0, this.C = i | 0, this.D = o | 0, this.E = a | 0, this.F = p | 0, this.G = c | 0, this.H = g | 0;
  }
  process(e, t) {
    for (let S = 0; S < 16; S++, t += 4)
      ur[S] = e.getUint32(t, !1);
    for (let S = 16; S < 64; S++) {
      const M = ur[S - 15], I = ur[S - 2], _ = Ht(M, 7) ^ Ht(M, 18) ^ M >>> 3, E = Ht(I, 17) ^ Ht(I, 19) ^ I >>> 10;
      ur[S] = E + ur[S - 7] + _ + ur[S - 16] | 0;
    }
    let { A: i, B: o, C: a, D: p, E: c, F: g, G: h, H: m } = this;
    for (let S = 0; S < 64; S++) {
      const M = Ht(c, 6) ^ Ht(c, 11) ^ Ht(c, 25), I = m + M + rl(c, g, h) + hl[S] + ur[S] | 0, E = (Ht(i, 2) ^ Ht(i, 13) ^ Ht(i, 22)) + il(i, o, a) | 0;
      m = h, h = g, g = c, c = p + I | 0, p = a, a = o, o = i, i = I + E | 0;
    }
    i = i + this.A | 0, o = o + this.B | 0, a = a + this.C | 0, p = p + this.D | 0, c = c + this.E | 0, g = g + this.F | 0, h = h + this.G | 0, m = m + this.H | 0, this.set(i, o, a, p, c, g, h, m);
  }
  roundClean() {
    mr(ur);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0), mr(this.buffer);
  }
}, qs = class extends bn {
  constructor() {
    super(28), this.A = sr[0] | 0, this.B = sr[1] | 0, this.C = sr[2] | 0, this.D = sr[3] | 0, this.E = sr[4] | 0, this.F = sr[5] | 0, this.G = sr[6] | 0, this.H = sr[7] | 0;
  }
};
const Ds = nl([
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
].map((r) => BigInt(r))), dl = Ds[0], pl = Ds[1], fr = /* @__PURE__ */ new Uint32Array(80), cr = /* @__PURE__ */ new Uint32Array(80);
let hi = class extends Ks {
  constructor(e = 64) {
    super(128, e, 16, !1), this.Ah = At[0] | 0, this.Al = At[1] | 0, this.Bh = At[2] | 0, this.Bl = At[3] | 0, this.Ch = At[4] | 0, this.Cl = At[5] | 0, this.Dh = At[6] | 0, this.Dl = At[7] | 0, this.Eh = At[8] | 0, this.El = At[9] | 0, this.Fh = At[10] | 0, this.Fl = At[11] | 0, this.Gh = At[12] | 0, this.Gl = At[13] | 0, this.Hh = At[14] | 0, this.Hl = At[15] | 0;
  }
  // prettier-ignore
  get() {
    const { Ah: e, Al: t, Bh: i, Bl: o, Ch: a, Cl: p, Dh: c, Dl: g, Eh: h, El: m, Fh: S, Fl: M, Gh: I, Gl: _, Hh: E, Hl: O } = this;
    return [e, t, i, o, a, p, c, g, h, m, S, M, I, _, E, O];
  }
  // prettier-ignore
  set(e, t, i, o, a, p, c, g, h, m, S, M, I, _, E, O) {
    this.Ah = e | 0, this.Al = t | 0, this.Bh = i | 0, this.Bl = o | 0, this.Ch = a | 0, this.Cl = p | 0, this.Dh = c | 0, this.Dl = g | 0, this.Eh = h | 0, this.El = m | 0, this.Fh = S | 0, this.Fl = M | 0, this.Gh = I | 0, this.Gl = _ | 0, this.Hh = E | 0, this.Hl = O | 0;
  }
  process(e, t) {
    for (let j = 0; j < 16; j++, t += 4)
      fr[j] = e.getUint32(t), cr[j] = e.getUint32(t += 4);
    for (let j = 16; j < 80; j++) {
      const F = fr[j - 15] | 0, C = cr[j - 15] | 0, q = Dr(F, C, 1) ^ Dr(F, C, 8) ^ Uo(F, C, 7), V = Hr(F, C, 1) ^ Hr(F, C, 8) ^ jo(F, C, 7), Z = fr[j - 2] | 0, K = cr[j - 2] | 0, G = Dr(Z, K, 19) ^ gi(Z, K, 61) ^ Uo(Z, K, 6), z = Hr(Z, K, 19) ^ yi(Z, K, 61) ^ jo(Z, K, 6), f = ul(V, z, cr[j - 7], cr[j - 16]), u = fl(f, q, G, fr[j - 7], fr[j - 16]);
      fr[j] = u | 0, cr[j] = f | 0;
    }
    let { Ah: i, Al: o, Bh: a, Bl: p, Ch: c, Cl: g, Dh: h, Dl: m, Eh: S, El: M, Fh: I, Fl: _, Gh: E, Gl: O, Hh: N, Hl: U } = this;
    for (let j = 0; j < 80; j++) {
      const F = Dr(S, M, 14) ^ Dr(S, M, 18) ^ gi(S, M, 41), C = Hr(S, M, 14) ^ Hr(S, M, 18) ^ yi(S, M, 41), q = S & I ^ ~S & E, V = M & _ ^ ~M & O, Z = cl(U, C, V, pl[j], cr[j]), K = ll(Z, N, F, q, dl[j], fr[j]), G = Z | 0, z = Dr(i, o, 28) ^ gi(i, o, 34) ^ gi(i, o, 39), f = Hr(i, o, 28) ^ yi(i, o, 34) ^ yi(i, o, 39), u = i & a ^ i & c ^ a & c, n = o & p ^ o & g ^ p & g;
      N = E | 0, U = O | 0, E = I | 0, O = _ | 0, I = S | 0, _ = M | 0, { h: S, l: M } = Qt(h | 0, m | 0, K | 0, G | 0), h = c | 0, m = g | 0, c = a | 0, g = p | 0, a = i | 0, p = o | 0;
      const s = ol(G, f, n);
      i = sl(s, K, z, u), o = s | 0;
    }
    ({ h: i, l: o } = Qt(this.Ah | 0, this.Al | 0, i | 0, o | 0)), { h: a, l: p } = Qt(this.Bh | 0, this.Bl | 0, a | 0, p | 0), { h: c, l: g } = Qt(this.Ch | 0, this.Cl | 0, c | 0, g | 0), { h, l: m } = Qt(this.Dh | 0, this.Dl | 0, h | 0, m | 0), { h: S, l: M } = Qt(this.Eh | 0, this.El | 0, S | 0, M | 0), { h: I, l: _ } = Qt(this.Fh | 0, this.Fl | 0, I | 0, _ | 0), { h: E, l: O } = Qt(this.Gh | 0, this.Gl | 0, E | 0, O | 0), { h: N, l: U } = Qt(this.Hh | 0, this.Hl | 0, N | 0, U | 0), this.set(i, o, a, p, c, g, h, m, S, M, I, _, E, O, N, U);
  }
  roundClean() {
    mr(fr, cr);
  }
  destroy() {
    mr(this.buffer), this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
}, Hs = class extends hi {
  constructor() {
    super(48), this.Ah = St[0] | 0, this.Al = St[1] | 0, this.Bh = St[2] | 0, this.Bl = St[3] | 0, this.Ch = St[4] | 0, this.Cl = St[5] | 0, this.Dh = St[6] | 0, this.Dl = St[7] | 0, this.Eh = St[8] | 0, this.El = St[9] | 0, this.Fh = St[10] | 0, this.Fl = St[11] | 0, this.Gh = St[12] | 0, this.Gl = St[13] | 0, this.Hh = St[14] | 0, this.Hl = St[15] | 0;
  }
};
const _t = /* @__PURE__ */ Uint32Array.from([
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
]), Mt = /* @__PURE__ */ Uint32Array.from([
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
let Vs = class extends hi {
  constructor() {
    super(28), this.Ah = _t[0] | 0, this.Al = _t[1] | 0, this.Bh = _t[2] | 0, this.Bl = _t[3] | 0, this.Ch = _t[4] | 0, this.Cl = _t[5] | 0, this.Dh = _t[6] | 0, this.Dl = _t[7] | 0, this.Eh = _t[8] | 0, this.El = _t[9] | 0, this.Fh = _t[10] | 0, this.Fl = _t[11] | 0, this.Gh = _t[12] | 0, this.Gl = _t[13] | 0, this.Hh = _t[14] | 0, this.Hl = _t[15] | 0;
  }
}, Gs = class extends hi {
  constructor() {
    super(32), this.Ah = Mt[0] | 0, this.Al = Mt[1] | 0, this.Bh = Mt[2] | 0, this.Bl = Mt[3] | 0, this.Ch = Mt[4] | 0, this.Cl = Mt[5] | 0, this.Dh = Mt[6] | 0, this.Dl = Mt[7] | 0, this.Eh = Mt[8] | 0, this.El = Mt[9] | 0, this.Fh = Mt[10] | 0, this.Fl = Mt[11] | 0, this.Gh = Mt[12] | 0, this.Gl = Mt[13] | 0, this.Hh = Mt[14] | 0, this.Hl = Mt[15] | 0;
  }
};
const ml = /* @__PURE__ */ vr(() => new bn()), bl = /* @__PURE__ */ vr(() => new qs()), vl = /* @__PURE__ */ vr(() => new hi()), gl = /* @__PURE__ */ vr(() => new Hs()), yl = /* @__PURE__ */ vr(() => new Gs()), wl = /* @__PURE__ */ vr(() => new Vs()), xl = bn, kl = ml, Sl = qs, Al = bl, _l = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  SHA224: Sl,
  SHA256: xl,
  sha224: Al,
  sha256: kl
}, Symbol.toStringTag, { value: "Module" })), Ml = /* @__PURE__ */ fi(_l), Bl = hi, Il = vl, El = Hs, Pl = gl, Tl = Vs, zl = wl, Ol = Gs, Nl = yl, Cl = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  SHA384: El,
  SHA512: Bl,
  SHA512_224: Tl,
  SHA512_256: Ol,
  sha384: Pl,
  sha512: Il,
  sha512_224: zl,
  sha512_256: Nl
}, Symbol.toStringTag, { value: "Module" })), Fl = /* @__PURE__ */ fi(Cl);
class Ws extends mn {
  constructor(e, t) {
    super(), this.finished = !1, this.destroyed = !1, ln(e);
    const i = $r(t);
    if (this.iHash = e.create(), typeof this.iHash.update != "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen, this.outputLen = this.iHash.outputLen;
    const o = this.blockLen, a = new Uint8Array(o);
    a.set(i.length > o ? e.create().update(i).digest() : i);
    for (let p = 0; p < a.length; p++)
      a[p] ^= 54;
    this.iHash.update(a), this.oHash = e.create();
    for (let p = 0; p < a.length; p++)
      a[p] ^= 106;
    this.oHash.update(a), mr(a);
  }
  update(e) {
    return si(this), this.iHash.update(e), this;
  }
  digestInto(e) {
    si(this), br(e, this.outputLen), this.finished = !0, this.iHash.digestInto(e), this.oHash.update(e), this.oHash.digestInto(e), this.destroy();
  }
  digest() {
    const e = new Uint8Array(this.oHash.outputLen);
    return this.digestInto(e), e;
  }
  _cloneInto(e) {
    e || (e = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash: t, iHash: i, finished: o, destroyed: a, blockLen: p, outputLen: c } = this;
    return e = e, e.finished = o, e.destroyed = a, e.blockLen = p, e.outputLen = c, e.oHash = t._cloneInto(e.oHash), e.iHash = i._cloneInto(e.iHash), e;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = !0, this.oHash.destroy(), this.iHash.destroy();
  }
}
const Js = (r, e, t) => new Ws(r, e).update(t).digest();
Js.create = (r, e) => new Ws(r, e);
function Ys(r, e, t, i) {
  ln(r);
  const o = Ls({ dkLen: 32, asyncTick: 10 }, i), { c: a, dkLen: p, asyncTick: c } = o;
  if (Yr(a), Yr(p), Yr(c), a < 1)
    throw new Error("iterations (c) should be >= 1");
  const g = Da(e), h = Da(t), m = new Uint8Array(p), S = Js.create(r, g), M = S._cloneInto().update(h);
  return { c: a, dkLen: p, asyncTick: c, DK: m, PRF: S, PRFSalt: M };
}
function Xs(r, e, t, i, o) {
  return r.destroy(), e.destroy(), i && i.destroy(), mr(o), t;
}
function Rl(r, e, t, i) {
  const { c: o, dkLen: a, DK: p, PRF: c, PRFSalt: g } = Ys(r, e, t, i);
  let h;
  const m = new Uint8Array(4), S = Xr(m), M = new Uint8Array(c.outputLen);
  for (let I = 1, _ = 0; _ < a; I++, _ += c.outputLen) {
    const E = p.subarray(_, _ + c.outputLen);
    S.setInt32(0, I, !1), (h = g._cloneInto(h)).update(m).digestInto(M), E.set(M.subarray(0, E.length));
    for (let O = 1; O < o; O++) {
      c._cloneInto(h).update(M).digestInto(M);
      for (let N = 0; N < E.length; N++)
        E[N] ^= M[N];
    }
  }
  return Xs(c, g, p, h, M);
}
async function Ll(r, e, t, i) {
  const { c: o, dkLen: a, asyncTick: p, DK: c, PRF: g, PRFSalt: h } = Ys(r, e, t, i);
  let m;
  const S = new Uint8Array(4), M = Xr(S), I = new Uint8Array(g.outputLen);
  for (let _ = 1, E = 0; E < a; _++, E += g.outputLen) {
    const O = c.subarray(E, E + g.outputLen);
    M.setInt32(0, _, !1), (m = h._cloneInto(m)).update(S).digestInto(I), O.set(I.subarray(0, O.length)), await Rs(o - 1, p, () => {
      g._cloneInto(m).update(I).digestInto(I);
      for (let N = 0; N < O.length; N++)
        O[N] ^= I[N];
    });
  }
  return Xs(g, h, c, m, I);
}
const Ul = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  pbkdf2: Rl,
  pbkdf2Async: Ll
}, Symbol.toStringTag, { value: "Module" })), jl = /* @__PURE__ */ fi(Ul), Kl = /* @__PURE__ */ fi(el);
var Ot = {};
const ql = /* @__PURE__ */ JSON.parse('["abdikace","abeceda","adresa","agrese","akce","aktovka","alej","alkohol","amputace","ananas","andulka","anekdota","anketa","antika","anulovat","archa","arogance","asfalt","asistent","aspirace","astma","astronom","atlas","atletika","atol","autobus","azyl","babka","bachor","bacil","baculka","badatel","bageta","bagr","bahno","bakterie","balada","baletka","balkon","balonek","balvan","balza","bambus","bankomat","barbar","baret","barman","baroko","barva","baterka","batoh","bavlna","bazalka","bazilika","bazuka","bedna","beran","beseda","bestie","beton","bezinka","bezmoc","beztak","bicykl","bidlo","biftek","bikiny","bilance","biograf","biolog","bitva","bizon","blahobyt","blatouch","blecha","bledule","blesk","blikat","blizna","blokovat","bloudit","blud","bobek","bobr","bodlina","bodnout","bohatost","bojkot","bojovat","bokorys","bolest","borec","borovice","bota","boubel","bouchat","bouda","boule","bourat","boxer","bradavka","brambora","branka","bratr","brepta","briketa","brko","brloh","bronz","broskev","brunetka","brusinka","brzda","brzy","bublina","bubnovat","buchta","buditel","budka","budova","bufet","bujarost","bukvice","buldok","bulva","bunda","bunkr","burza","butik","buvol","buzola","bydlet","bylina","bytovka","bzukot","capart","carevna","cedr","cedule","cejch","cejn","cela","celer","celkem","celnice","cenina","cennost","cenovka","centrum","cenzor","cestopis","cetka","chalupa","chapadlo","charita","chata","chechtat","chemie","chichot","chirurg","chlad","chleba","chlubit","chmel","chmura","chobot","chochol","chodba","cholera","chomout","chopit","choroba","chov","chrapot","chrlit","chrt","chrup","chtivost","chudina","chutnat","chvat","chvilka","chvost","chyba","chystat","chytit","cibule","cigareta","cihelna","cihla","cinkot","cirkus","cisterna","citace","citrus","cizinec","cizost","clona","cokoliv","couvat","ctitel","ctnost","cudnost","cuketa","cukr","cupot","cvaknout","cval","cvik","cvrkot","cyklista","daleko","dareba","datel","datum","dcera","debata","dechovka","decibel","deficit","deflace","dekl","dekret","demokrat","deprese","derby","deska","detektiv","dikobraz","diktovat","dioda","diplom","disk","displej","divadlo","divoch","dlaha","dlouho","dluhopis","dnes","dobro","dobytek","docent","dochutit","dodnes","dohled","dohoda","dohra","dojem","dojnice","doklad","dokola","doktor","dokument","dolar","doleva","dolina","doma","dominant","domluvit","domov","donutit","dopad","dopis","doplnit","doposud","doprovod","dopustit","dorazit","dorost","dort","dosah","doslov","dostatek","dosud","dosyta","dotaz","dotek","dotknout","doufat","doutnat","dovozce","dozadu","doznat","dozorce","drahota","drak","dramatik","dravec","draze","drdol","drobnost","drogerie","drozd","drsnost","drtit","drzost","duben","duchovno","dudek","duha","duhovka","dusit","dusno","dutost","dvojice","dvorec","dynamit","ekolog","ekonomie","elektron","elipsa","email","emise","emoce","empatie","epizoda","epocha","epopej","epos","esej","esence","eskorta","eskymo","etiketa","euforie","evoluce","exekuce","exkurze","expedice","exploze","export","extrakt","facka","fajfka","fakulta","fanatik","fantazie","farmacie","favorit","fazole","federace","fejeton","fenka","fialka","figurant","filozof","filtr","finance","finta","fixace","fjord","flanel","flirt","flotila","fond","fosfor","fotbal","fotka","foton","frakce","freska","fronta","fukar","funkce","fyzika","galeje","garant","genetika","geolog","gilotina","glazura","glejt","golem","golfista","gotika","graf","gramofon","granule","grep","gril","grog","groteska","guma","hadice","hadr","hala","halenka","hanba","hanopis","harfa","harpuna","havran","hebkost","hejkal","hejno","hejtman","hektar","helma","hematom","herec","herna","heslo","hezky","historik","hladovka","hlasivky","hlava","hledat","hlen","hlodavec","hloh","hloupost","hltat","hlubina","hluchota","hmat","hmota","hmyz","hnis","hnojivo","hnout","hoblina","hoboj","hoch","hodiny","hodlat","hodnota","hodovat","hojnost","hokej","holinka","holka","holub","homole","honitba","honorace","horal","horda","horizont","horko","horlivec","hormon","hornina","horoskop","horstvo","hospoda","hostina","hotovost","houba","houf","houpat","houska","hovor","hradba","hranice","hravost","hrazda","hrbolek","hrdina","hrdlo","hrdost","hrnek","hrobka","hromada","hrot","hrouda","hrozen","hrstka","hrubost","hryzat","hubenost","hubnout","hudba","hukot","humr","husita","hustota","hvozd","hybnost","hydrant","hygiena","hymna","hysterik","idylka","ihned","ikona","iluze","imunita","infekce","inflace","inkaso","inovace","inspekce","internet","invalida","investor","inzerce","ironie","jablko","jachta","jahoda","jakmile","jakost","jalovec","jantar","jarmark","jaro","jasan","jasno","jatka","javor","jazyk","jedinec","jedle","jednatel","jehlan","jekot","jelen","jelito","jemnost","jenom","jepice","jeseter","jevit","jezdec","jezero","jinak","jindy","jinoch","jiskra","jistota","jitrnice","jizva","jmenovat","jogurt","jurta","kabaret","kabel","kabinet","kachna","kadet","kadidlo","kahan","kajak","kajuta","kakao","kaktus","kalamita","kalhoty","kalibr","kalnost","kamera","kamkoliv","kamna","kanibal","kanoe","kantor","kapalina","kapela","kapitola","kapka","kaple","kapota","kapr","kapusta","kapybara","karamel","karotka","karton","kasa","katalog","katedra","kauce","kauza","kavalec","kazajka","kazeta","kazivost","kdekoliv","kdesi","kedluben","kemp","keramika","kino","klacek","kladivo","klam","klapot","klasika","klaun","klec","klenba","klepat","klesnout","klid","klima","klisna","klobouk","klokan","klopa","kloub","klubovna","klusat","kluzkost","kmen","kmitat","kmotr","kniha","knot","koalice","koberec","kobka","kobliha","kobyla","kocour","kohout","kojenec","kokos","koktejl","kolaps","koleda","kolize","kolo","komando","kometa","komik","komnata","komora","kompas","komunita","konat","koncept","kondice","konec","konfese","kongres","konina","konkurs","kontakt","konzerva","kopanec","kopie","kopnout","koprovka","korbel","korektor","kormidlo","koroptev","korpus","koruna","koryto","korzet","kosatec","kostka","kotel","kotleta","kotoul","koukat","koupelna","kousek","kouzlo","kovboj","koza","kozoroh","krabice","krach","krajina","kralovat","krasopis","kravata","kredit","krejcar","kresba","kreveta","kriket","kritik","krize","krkavec","krmelec","krmivo","krocan","krok","kronika","kropit","kroupa","krovka","krtek","kruhadlo","krupice","krutost","krvinka","krychle","krypta","krystal","kryt","kudlanka","kufr","kujnost","kukla","kulajda","kulich","kulka","kulomet","kultura","kuna","kupodivu","kurt","kurzor","kutil","kvalita","kvasinka","kvestor","kynolog","kyselina","kytara","kytice","kytka","kytovec","kyvadlo","labrador","lachtan","ladnost","laik","lakomec","lamela","lampa","lanovka","lasice","laso","lastura","latinka","lavina","lebka","leckdy","leden","lednice","ledovka","ledvina","legenda","legie","legrace","lehce","lehkost","lehnout","lektvar","lenochod","lentilka","lepenka","lepidlo","letadlo","letec","letmo","letokruh","levhart","levitace","levobok","libra","lichotka","lidojed","lidskost","lihovina","lijavec","lilek","limetka","linie","linka","linoleum","listopad","litina","litovat","lobista","lodivod","logika","logoped","lokalita","loket","lomcovat","lopata","lopuch","lord","losos","lotr","loudal","louh","louka","louskat","lovec","lstivost","lucerna","lucifer","lump","lusk","lustrace","lvice","lyra","lyrika","lysina","madam","madlo","magistr","mahagon","majetek","majitel","majorita","makak","makovice","makrela","malba","malina","malovat","malvice","maminka","mandle","manko","marnost","masakr","maskot","masopust","matice","matrika","maturita","mazanec","mazivo","mazlit","mazurka","mdloba","mechanik","meditace","medovina","melasa","meloun","mentolka","metla","metoda","metr","mezera","migrace","mihnout","mihule","mikina","mikrofon","milenec","milimetr","milost","mimika","mincovna","minibar","minomet","minulost","miska","mistr","mixovat","mladost","mlha","mlhovina","mlok","mlsat","mluvit","mnich","mnohem","mobil","mocnost","modelka","modlitba","mohyla","mokro","molekula","momentka","monarcha","monokl","monstrum","montovat","monzun","mosaz","moskyt","most","motivace","motorka","motyka","moucha","moudrost","mozaika","mozek","mozol","mramor","mravenec","mrkev","mrtvola","mrzet","mrzutost","mstitel","mudrc","muflon","mulat","mumie","munice","muset","mutace","muzeum","muzikant","myslivec","mzda","nabourat","nachytat","nadace","nadbytek","nadhoz","nadobro","nadpis","nahlas","nahnat","nahodile","nahradit","naivita","najednou","najisto","najmout","naklonit","nakonec","nakrmit","nalevo","namazat","namluvit","nanometr","naoko","naopak","naostro","napadat","napevno","naplnit","napnout","naposled","naprosto","narodit","naruby","narychlo","nasadit","nasekat","naslepo","nastat","natolik","navenek","navrch","navzdory","nazvat","nebe","nechat","necky","nedaleko","nedbat","neduh","negace","nehet","nehoda","nejen","nejprve","neklid","nelibost","nemilost","nemoc","neochota","neonka","nepokoj","nerost","nerv","nesmysl","nesoulad","netvor","neuron","nevina","nezvykle","nicota","nijak","nikam","nikdy","nikl","nikterak","nitro","nocleh","nohavice","nominace","nora","norek","nositel","nosnost","nouze","noviny","novota","nozdra","nuda","nudle","nuget","nutit","nutnost","nutrie","nymfa","obal","obarvit","obava","obdiv","obec","obehnat","obejmout","obezita","obhajoba","obilnice","objasnit","objekt","obklopit","oblast","oblek","obliba","obloha","obluda","obnos","obohatit","obojek","obout","obrazec","obrna","obruba","obrys","obsah","obsluha","obstarat","obuv","obvaz","obvinit","obvod","obvykle","obyvatel","obzor","ocas","ocel","ocenit","ochladit","ochota","ochrana","ocitnout","odboj","odbyt","odchod","odcizit","odebrat","odeslat","odevzdat","odezva","odhadce","odhodit","odjet","odjinud","odkaz","odkoupit","odliv","odluka","odmlka","odolnost","odpad","odpis","odplout","odpor","odpustit","odpykat","odrazka","odsoudit","odstup","odsun","odtok","odtud","odvaha","odveta","odvolat","odvracet","odznak","ofina","ofsajd","ohlas","ohnisko","ohrada","ohrozit","ohryzek","okap","okenice","oklika","okno","okouzlit","okovy","okrasa","okres","okrsek","okruh","okupant","okurka","okusit","olejnina","olizovat","omak","omeleta","omezit","omladina","omlouvat","omluva","omyl","onehdy","opakovat","opasek","operace","opice","opilost","opisovat","opora","opozice","opravdu","oproti","orbital","orchestr","orgie","orlice","orloj","ortel","osada","oschnout","osika","osivo","oslava","oslepit","oslnit","oslovit","osnova","osoba","osolit","ospalec","osten","ostraha","ostuda","ostych","osvojit","oteplit","otisk","otop","otrhat","otrlost","otrok","otruby","otvor","ovanout","ovar","oves","ovlivnit","ovoce","oxid","ozdoba","pachatel","pacient","padouch","pahorek","pakt","palanda","palec","palivo","paluba","pamflet","pamlsek","panenka","panika","panna","panovat","panstvo","pantofle","paprika","parketa","parodie","parta","paruka","paryba","paseka","pasivita","pastelka","patent","patrona","pavouk","pazneht","pazourek","pecka","pedagog","pejsek","peklo","peloton","penalta","pendrek","penze","periskop","pero","pestrost","petarda","petice","petrolej","pevnina","pexeso","pianista","piha","pijavice","pikle","piknik","pilina","pilnost","pilulka","pinzeta","pipeta","pisatel","pistole","pitevna","pivnice","pivovar","placenta","plakat","plamen","planeta","plastika","platit","plavidlo","plaz","plech","plemeno","plenta","ples","pletivo","plevel","plivat","plnit","plno","plocha","plodina","plomba","plout","pluk","plyn","pobavit","pobyt","pochod","pocit","poctivec","podat","podcenit","podepsat","podhled","podivit","podklad","podmanit","podnik","podoba","podpora","podraz","podstata","podvod","podzim","poezie","pohanka","pohnutka","pohovor","pohroma","pohyb","pointa","pojistka","pojmout","pokazit","pokles","pokoj","pokrok","pokuta","pokyn","poledne","polibek","polknout","poloha","polynom","pomalu","pominout","pomlka","pomoc","pomsta","pomyslet","ponechat","ponorka","ponurost","popadat","popel","popisek","poplach","poprosit","popsat","popud","poradce","porce","porod","porucha","poryv","posadit","posed","posila","poskok","poslanec","posoudit","pospolu","postava","posudek","posyp","potah","potkan","potlesk","potomek","potrava","potupa","potvora","poukaz","pouto","pouzdro","povaha","povidla","povlak","povoz","povrch","povstat","povyk","povzdech","pozdrav","pozemek","poznatek","pozor","pozvat","pracovat","prahory","praktika","prales","praotec","praporek","prase","pravda","princip","prkno","probudit","procento","prodej","profese","prohra","projekt","prolomit","promile","pronikat","propad","prorok","prosba","proton","proutek","provaz","prskavka","prsten","prudkost","prut","prvek","prvohory","psanec","psovod","pstruh","ptactvo","puberta","puch","pudl","pukavec","puklina","pukrle","pult","pumpa","punc","pupen","pusa","pusinka","pustina","putovat","putyka","pyramida","pysk","pytel","racek","rachot","radiace","radnice","radon","raft","ragby","raketa","rakovina","rameno","rampouch","rande","rarach","rarita","rasovna","rastr","ratolest","razance","razidlo","reagovat","reakce","recept","redaktor","referent","reflex","rejnok","reklama","rekord","rekrut","rektor","reputace","revize","revma","revolver","rezerva","riskovat","riziko","robotika","rodokmen","rohovka","rokle","rokoko","romaneto","ropovod","ropucha","rorejs","rosol","rostlina","rotmistr","rotoped","rotunda","roubenka","roucho","roup","roura","rovina","rovnice","rozbor","rozchod","rozdat","rozeznat","rozhodce","rozinka","rozjezd","rozkaz","rozloha","rozmar","rozpad","rozruch","rozsah","roztok","rozum","rozvod","rubrika","ruchadlo","rukavice","rukopis","ryba","rybolov","rychlost","rydlo","rypadlo","rytina","ryzost","sadista","sahat","sako","samec","samizdat","samota","sanitka","sardinka","sasanka","satelit","sazba","sazenice","sbor","schovat","sebranka","secese","sedadlo","sediment","sedlo","sehnat","sejmout","sekera","sekta","sekunda","sekvoje","semeno","seno","servis","sesadit","seshora","seskok","seslat","sestra","sesuv","sesypat","setba","setina","setkat","setnout","setrvat","sever","seznam","shoda","shrnout","sifon","silnice","sirka","sirotek","sirup","situace","skafandr","skalisko","skanzen","skaut","skeptik","skica","skladba","sklenice","sklo","skluz","skoba","skokan","skoro","skripta","skrz","skupina","skvost","skvrna","slabika","sladidlo","slanina","slast","slavnost","sledovat","slepec","sleva","slezina","slib","slina","sliznice","slon","sloupek","slovo","sluch","sluha","slunce","slupka","slza","smaragd","smetana","smilstvo","smlouva","smog","smrad","smrk","smrtka","smutek","smysl","snad","snaha","snob","sobota","socha","sodovka","sokol","sopka","sotva","souboj","soucit","soudce","souhlas","soulad","soumrak","souprava","soused","soutok","souviset","spalovna","spasitel","spis","splav","spodek","spojenec","spolu","sponzor","spornost","spousta","sprcha","spustit","sranda","sraz","srdce","srna","srnec","srovnat","srpen","srst","srub","stanice","starosta","statika","stavba","stehno","stezka","stodola","stolek","stopa","storno","stoupat","strach","stres","strhnout","strom","struna","studna","stupnice","stvol","styk","subjekt","subtropy","suchar","sudost","sukno","sundat","sunout","surikata","surovina","svah","svalstvo","svetr","svatba","svazek","svisle","svitek","svoboda","svodidlo","svorka","svrab","sykavka","sykot","synek","synovec","sypat","sypkost","syrovost","sysel","sytost","tabletka","tabule","tahoun","tajemno","tajfun","tajga","tajit","tajnost","taktika","tamhle","tampon","tancovat","tanec","tanker","tapeta","tavenina","tazatel","technika","tehdy","tekutina","telefon","temnota","tendence","tenista","tenor","teplota","tepna","teprve","terapie","termoska","textil","ticho","tiskopis","titulek","tkadlec","tkanina","tlapka","tleskat","tlukot","tlupa","tmel","toaleta","topinka","topol","torzo","touha","toulec","tradice","traktor","tramp","trasa","traverza","trefit","trest","trezor","trhavina","trhlina","trochu","trojice","troska","trouba","trpce","trpitel","trpkost","trubec","truchlit","truhlice","trus","trvat","tudy","tuhnout","tuhost","tundra","turista","turnaj","tuzemsko","tvaroh","tvorba","tvrdost","tvrz","tygr","tykev","ubohost","uboze","ubrat","ubrousek","ubrus","ubytovna","ucho","uctivost","udivit","uhradit","ujednat","ujistit","ujmout","ukazatel","uklidnit","uklonit","ukotvit","ukrojit","ulice","ulita","ulovit","umyvadlo","unavit","uniforma","uniknout","upadnout","uplatnit","uplynout","upoutat","upravit","uran","urazit","usednout","usilovat","usmrtit","usnadnit","usnout","usoudit","ustlat","ustrnout","utahovat","utkat","utlumit","utonout","utopenec","utrousit","uvalit","uvolnit","uvozovka","uzdravit","uzel","uzenina","uzlina","uznat","vagon","valcha","valoun","vana","vandal","vanilka","varan","varhany","varovat","vcelku","vchod","vdova","vedro","vegetace","vejce","velbloud","veletrh","velitel","velmoc","velryba","venkov","veranda","verze","veselka","veskrze","vesnice","vespodu","vesta","veterina","veverka","vibrace","vichr","videohra","vidina","vidle","vila","vinice","viset","vitalita","vize","vizitka","vjezd","vklad","vkus","vlajka","vlak","vlasec","vlevo","vlhkost","vliv","vlnovka","vloupat","vnucovat","vnuk","voda","vodivost","vodoznak","vodstvo","vojensky","vojna","vojsko","volant","volba","volit","volno","voskovka","vozidlo","vozovna","vpravo","vrabec","vracet","vrah","vrata","vrba","vrcholek","vrhat","vrstva","vrtule","vsadit","vstoupit","vstup","vtip","vybavit","vybrat","vychovat","vydat","vydra","vyfotit","vyhledat","vyhnout","vyhodit","vyhradit","vyhubit","vyjasnit","vyjet","vyjmout","vyklopit","vykonat","vylekat","vymazat","vymezit","vymizet","vymyslet","vynechat","vynikat","vynutit","vypadat","vyplatit","vypravit","vypustit","vyrazit","vyrovnat","vyrvat","vyslovit","vysoko","vystavit","vysunout","vysypat","vytasit","vytesat","vytratit","vyvinout","vyvolat","vyvrhel","vyzdobit","vyznat","vzadu","vzbudit","vzchopit","vzdor","vzduch","vzdychat","vzestup","vzhledem","vzkaz","vzlykat","vznik","vzorek","vzpoura","vztah","vztek","xylofon","zabrat","zabydlet","zachovat","zadarmo","zadusit","zafoukat","zahltit","zahodit","zahrada","zahynout","zajatec","zajet","zajistit","zaklepat","zakoupit","zalepit","zamezit","zamotat","zamyslet","zanechat","zanikat","zaplatit","zapojit","zapsat","zarazit","zastavit","zasunout","zatajit","zatemnit","zatknout","zaujmout","zavalit","zavelet","zavinit","zavolat","zavrtat","zazvonit","zbavit","zbrusu","zbudovat","zbytek","zdaleka","zdarma","zdatnost","zdivo","zdobit","zdroj","zdvih","zdymadlo","zelenina","zeman","zemina","zeptat","zezadu","zezdola","zhatit","zhltnout","zhluboka","zhotovit","zhruba","zima","zimnice","zjemnit","zklamat","zkoumat","zkratka","zkumavka","zlato","zlehka","zloba","zlom","zlost","zlozvyk","zmapovat","zmar","zmatek","zmije","zmizet","zmocnit","zmodrat","zmrzlina","zmutovat","znak","znalost","znamenat","znovu","zobrazit","zotavit","zoubek","zoufale","zplodit","zpomalit","zprava","zprostit","zprudka","zprvu","zrada","zranit","zrcadlo","zrnitost","zrno","zrovna","zrychlit","zrzavost","zticha","ztratit","zubovina","zubr","zvednout","zvenku","zvesela","zvon","zvrat","zvukovod","zvyk"]'), Dl = /* @__PURE__ */ JSON.parse('["的","一","是","在","不","了","有","和","人","这","中","大","为","上","个","国","我","以","要","他","时","来","用","们","生","到","作","地","于","出","就","分","对","成","会","可","主","发","年","动","同","工","也","能","下","过","子","说","产","种","面","而","方","后","多","定","行","学","法","所","民","得","经","十","三","之","进","着","等","部","度","家","电","力","里","如","水","化","高","自","二","理","起","小","物","现","实","加","量","都","两","体","制","机","当","使","点","从","业","本","去","把","性","好","应","开","它","合","还","因","由","其","些","然","前","外","天","政","四","日","那","社","义","事","平","形","相","全","表","间","样","与","关","各","重","新","线","内","数","正","心","反","你","明","看","原","又","么","利","比","或","但","质","气","第","向","道","命","此","变","条","只","没","结","解","问","意","建","月","公","无","系","军","很","情","者","最","立","代","想","已","通","并","提","直","题","党","程","展","五","果","料","象","员","革","位","入","常","文","总","次","品","式","活","设","及","管","特","件","长","求","老","头","基","资","边","流","路","级","少","图","山","统","接","知","较","将","组","见","计","别","她","手","角","期","根","论","运","农","指","几","九","区","强","放","决","西","被","干","做","必","战","先","回","则","任","取","据","处","队","南","给","色","光","门","即","保","治","北","造","百","规","热","领","七","海","口","东","导","器","压","志","世","金","增","争","济","阶","油","思","术","极","交","受","联","什","认","六","共","权","收","证","改","清","美","再","采","转","更","单","风","切","打","白","教","速","花","带","安","场","身","车","例","真","务","具","万","每","目","至","达","走","积","示","议","声","报","斗","完","类","八","离","华","名","确","才","科","张","信","马","节","话","米","整","空","元","况","今","集","温","传","土","许","步","群","广","石","记","需","段","研","界","拉","林","律","叫","且","究","观","越","织","装","影","算","低","持","音","众","书","布","复","容","儿","须","际","商","非","验","连","断","深","难","近","矿","千","周","委","素","技","备","半","办","青","省","列","习","响","约","支","般","史","感","劳","便","团","往","酸","历","市","克","何","除","消","构","府","称","太","准","精","值","号","率","族","维","划","选","标","写","存","候","毛","亲","快","效","斯","院","查","江","型","眼","王","按","格","养","易","置","派","层","片","始","却","专","状","育","厂","京","识","适","属","圆","包","火","住","调","满","县","局","照","参","红","细","引","听","该","铁","价","严","首","底","液","官","德","随","病","苏","失","尔","死","讲","配","女","黄","推","显","谈","罪","神","艺","呢","席","含","企","望","密","批","营","项","防","举","球","英","氧","势","告","李","台","落","木","帮","轮","破","亚","师","围","注","远","字","材","排","供","河","态","封","另","施","减","树","溶","怎","止","案","言","士","均","武","固","叶","鱼","波","视","仅","费","紧","爱","左","章","早","朝","害","续","轻","服","试","食","充","兵","源","判","护","司","足","某","练","差","致","板","田","降","黑","犯","负","击","范","继","兴","似","余","坚","曲","输","修","故","城","夫","够","送","笔","船","占","右","财","吃","富","春","职","觉","汉","画","功","巴","跟","虽","杂","飞","检","吸","助","升","阳","互","初","创","抗","考","投","坏","策","古","径","换","未","跑","留","钢","曾","端","责","站","简","述","钱","副","尽","帝","射","草","冲","承","独","令","限","阿","宣","环","双","请","超","微","让","控","州","良","轴","找","否","纪","益","依","优","顶","础","载","倒","房","突","坐","粉","敌","略","客","袁","冷","胜","绝","析","块","剂","测","丝","协","诉","念","陈","仍","罗","盐","友","洋","错","苦","夜","刑","移","频","逐","靠","混","母","短","皮","终","聚","汽","村","云","哪","既","距","卫","停","烈","央","察","烧","迅","境","若","印","洲","刻","括","激","孔","搞","甚","室","待","核","校","散","侵","吧","甲","游","久","菜","味","旧","模","湖","货","损","预","阻","毫","普","稳","乙","妈","植","息","扩","银","语","挥","酒","守","拿","序","纸","医","缺","雨","吗","针","刘","啊","急","唱","误","训","愿","审","附","获","茶","鲜","粮","斤","孩","脱","硫","肥","善","龙","演","父","渐","血","欢","械","掌","歌","沙","刚","攻","谓","盾","讨","晚","粒","乱","燃","矛","乎","杀","药","宁","鲁","贵","钟","煤","读","班","伯","香","介","迫","句","丰","培","握","兰","担","弦","蛋","沉","假","穿","执","答","乐","谁","顺","烟","缩","征","脸","喜","松","脚","困","异","免","背","星","福","买","染","井","概","慢","怕","磁","倍","祖","皇","促","静","补","评","翻","肉","践","尼","衣","宽","扬","棉","希","伤","操","垂","秋","宜","氢","套","督","振","架","亮","末","宪","庆","编","牛","触","映","雷","销","诗","座","居","抓","裂","胞","呼","娘","景","威","绿","晶","厚","盟","衡","鸡","孙","延","危","胶","屋","乡","临","陆","顾","掉","呀","灯","岁","措","束","耐","剧","玉","赵","跳","哥","季","课","凯","胡","额","款","绍","卷","齐","伟","蒸","殖","永","宗","苗","川","炉","岩","弱","零","杨","奏","沿","露","杆","探","滑","镇","饭","浓","航","怀","赶","库","夺","伊","灵","税","途","灭","赛","归","召","鼓","播","盘","裁","险","康","唯","录","菌","纯","借","糖","盖","横","符","私","努","堂","域","枪","润","幅","哈","竟","熟","虫","泽","脑","壤","碳","欧","遍","侧","寨","敢","彻","虑","斜","薄","庭","纳","弹","饲","伸","折","麦","湿","暗","荷","瓦","塞","床","筑","恶","户","访","塔","奇","透","梁","刀","旋","迹","卡","氯","遇","份","毒","泥","退","洗","摆","灰","彩","卖","耗","夏","择","忙","铜","献","硬","予","繁","圈","雪","函","亦","抽","篇","阵","阴","丁","尺","追","堆","雄","迎","泛","爸","楼","避","谋","吨","野","猪","旗","累","偏","典","馆","索","秦","脂","潮","爷","豆","忽","托","惊","塑","遗","愈","朱","替","纤","粗","倾","尚","痛","楚","谢","奋","购","磨","君","池","旁","碎","骨","监","捕","弟","暴","割","贯","殊","释","词","亡","壁","顿","宝","午","尘","闻","揭","炮","残","冬","桥","妇","警","综","招","吴","付","浮","遭","徐","您","摇","谷","赞","箱","隔","订","男","吹","园","纷","唐","败","宋","玻","巨","耕","坦","荣","闭","湾","键","凡","驻","锅","救","恩","剥","凝","碱","齿","截","炼","麻","纺","禁","废","盛","版","缓","净","睛","昌","婚","涉","筒","嘴","插","岸","朗","庄","街","藏","姑","贸","腐","奴","啦","惯","乘","伙","恢","匀","纱","扎","辩","耳","彪","臣","亿","璃","抵","脉","秀","萨","俄","网","舞","店","喷","纵","寸","汗","挂","洪","贺","闪","柬","爆","烯","津","稻","墙","软","勇","像","滚","厘","蒙","芳","肯","坡","柱","荡","腿","仪","旅","尾","轧","冰","贡","登","黎","削","钻","勒","逃","障","氨","郭","峰","币","港","伏","轨","亩","毕","擦","莫","刺","浪","秘","援","株","健","售","股","岛","甘","泡","睡","童","铸","汤","阀","休","汇","舍","牧","绕","炸","哲","磷","绩","朋","淡","尖","启","陷","柴","呈","徒","颜","泪","稍","忘","泵","蓝","拖","洞","授","镜","辛","壮","锋","贫","虚","弯","摩","泰","幼","廷","尊","窗","纲","弄","隶","疑","氏","宫","姐","震","瑞","怪","尤","琴","循","描","膜","违","夹","腰","缘","珠","穷","森","枝","竹","沟","催","绳","忆","邦","剩","幸","浆","栏","拥","牙","贮","礼","滤","钠","纹","罢","拍","咱","喊","袖","埃","勤","罚","焦","潜","伍","墨","欲","缝","姓","刊","饱","仿","奖","铝","鬼","丽","跨","默","挖","链","扫","喝","袋","炭","污","幕","诸","弧","励","梅","奶","洁","灾","舟","鉴","苯","讼","抱","毁","懂","寒","智","埔","寄","届","跃","渡","挑","丹","艰","贝","碰","拔","爹","戴","码","梦","芽","熔","赤","渔","哭","敬","颗","奔","铅","仲","虎","稀","妹","乏","珍","申","桌","遵","允","隆","螺","仓","魏","锐","晓","氮","兼","隐","碍","赫","拨","忠","肃","缸","牵","抢","博","巧","壳","兄","杜","讯","诚","碧","祥","柯","页","巡","矩","悲","灌","龄","伦","票","寻","桂","铺","圣","恐","恰","郑","趣","抬","荒","腾","贴","柔","滴","猛","阔","辆","妻","填","撤","储","签","闹","扰","紫","砂","递","戏","吊","陶","伐","喂","疗","瓶","婆","抚","臂","摸","忍","虾","蜡","邻","胸","巩","挤","偶","弃","槽","劲","乳","邓","吉","仁","烂","砖","租","乌","舰","伴","瓜","浅","丙","暂","燥","橡","柳","迷","暖","牌","秧","胆","详","簧","踏","瓷","谱","呆","宾","糊","洛","辉","愤","竞","隙","怒","粘","乃","绪","肩","籍","敏","涂","熙","皆","侦","悬","掘","享","纠","醒","狂","锁","淀","恨","牲","霸","爬","赏","逆","玩","陵","祝","秒","浙","貌","役","彼","悉","鸭","趋","凤","晨","畜","辈","秩","卵","署","梯","炎","滩","棋","驱","筛","峡","冒","啥","寿","译","浸","泉","帽","迟","硅","疆","贷","漏","稿","冠","嫩","胁","芯","牢","叛","蚀","奥","鸣","岭","羊","凭","串","塘","绘","酵","融","盆","锡","庙","筹","冻","辅","摄","袭","筋","拒","僚","旱","钾","鸟","漆","沈","眉","疏","添","棒","穗","硝","韩","逼","扭","侨","凉","挺","碗","栽","炒","杯","患","馏","劝","豪","辽","勃","鸿","旦","吏","拜","狗","埋","辊","掩","饮","搬","骂","辞","勾","扣","估","蒋","绒","雾","丈","朵","姆","拟","宇","辑","陕","雕","偿","蓄","崇","剪","倡","厅","咬","驶","薯","刷","斥","番","赋","奉","佛","浇","漫","曼","扇","钙","桃","扶","仔","返","俗","亏","腔","鞋","棱","覆","框","悄","叔","撞","骗","勘","旺","沸","孤","吐","孟","渠","屈","疾","妙","惜","仰","狠","胀","谐","抛","霉","桑","岗","嘛","衰","盗","渗","脏","赖","涌","甜","曹","阅","肌","哩","厉","烃","纬","毅","昨","伪","症","煮","叹","钉","搭","茎","笼","酷","偷","弓","锥","恒","杰","坑","鼻","翼","纶","叙","狱","逮","罐","络","棚","抑","膨","蔬","寺","骤","穆","冶","枯","册","尸","凸","绅","坯","牺","焰","轰","欣","晋","瘦","御","锭","锦","丧","旬","锻","垄","搜","扑","邀","亭","酯","迈","舒","脆","酶","闲","忧","酚","顽","羽","涨","卸","仗","陪","辟","惩","杭","姚","肚","捉","飘","漂","昆","欺","吾","郎","烷","汁","呵","饰","萧","雅","邮","迁","燕","撒","姻","赴","宴","烦","债","帐","斑","铃","旨","醇","董","饼","雏","姿","拌","傅","腹","妥","揉","贤","拆","歪","葡","胺","丢","浩","徽","昂","垫","挡","览","贪","慰","缴","汪","慌","冯","诺","姜","谊","凶","劣","诬","耀","昏","躺","盈","骑","乔","溪","丛","卢","抹","闷","咨","刮","驾","缆","悟","摘","铒","掷","颇","幻","柄","惠","惨","佳","仇","腊","窝","涤","剑","瞧","堡","泼","葱","罩","霍","捞","胎","苍","滨","俩","捅","湘","砍","霞","邵","萄","疯","淮","遂","熊","粪","烘","宿","档","戈","驳","嫂","裕","徙","箭","捐","肠","撑","晒","辨","殿","莲","摊","搅","酱","屏","疫","哀","蔡","堵","沫","皱","畅","叠","阁","莱","敲","辖","钩","痕","坝","巷","饿","祸","丘","玄","溜","曰","逻","彭","尝","卿","妨","艇","吞","韦","怨","矮","歇"]'), Hl = /* @__PURE__ */ JSON.parse('["的","一","是","在","不","了","有","和","人","這","中","大","為","上","個","國","我","以","要","他","時","來","用","們","生","到","作","地","於","出","就","分","對","成","會","可","主","發","年","動","同","工","也","能","下","過","子","說","產","種","面","而","方","後","多","定","行","學","法","所","民","得","經","十","三","之","進","著","等","部","度","家","電","力","裡","如","水","化","高","自","二","理","起","小","物","現","實","加","量","都","兩","體","制","機","當","使","點","從","業","本","去","把","性","好","應","開","它","合","還","因","由","其","些","然","前","外","天","政","四","日","那","社","義","事","平","形","相","全","表","間","樣","與","關","各","重","新","線","內","數","正","心","反","你","明","看","原","又","麼","利","比","或","但","質","氣","第","向","道","命","此","變","條","只","沒","結","解","問","意","建","月","公","無","系","軍","很","情","者","最","立","代","想","已","通","並","提","直","題","黨","程","展","五","果","料","象","員","革","位","入","常","文","總","次","品","式","活","設","及","管","特","件","長","求","老","頭","基","資","邊","流","路","級","少","圖","山","統","接","知","較","將","組","見","計","別","她","手","角","期","根","論","運","農","指","幾","九","區","強","放","決","西","被","幹","做","必","戰","先","回","則","任","取","據","處","隊","南","給","色","光","門","即","保","治","北","造","百","規","熱","領","七","海","口","東","導","器","壓","志","世","金","增","爭","濟","階","油","思","術","極","交","受","聯","什","認","六","共","權","收","證","改","清","美","再","採","轉","更","單","風","切","打","白","教","速","花","帶","安","場","身","車","例","真","務","具","萬","每","目","至","達","走","積","示","議","聲","報","鬥","完","類","八","離","華","名","確","才","科","張","信","馬","節","話","米","整","空","元","況","今","集","溫","傳","土","許","步","群","廣","石","記","需","段","研","界","拉","林","律","叫","且","究","觀","越","織","裝","影","算","低","持","音","眾","書","布","复","容","兒","須","際","商","非","驗","連","斷","深","難","近","礦","千","週","委","素","技","備","半","辦","青","省","列","習","響","約","支","般","史","感","勞","便","團","往","酸","歷","市","克","何","除","消","構","府","稱","太","準","精","值","號","率","族","維","劃","選","標","寫","存","候","毛","親","快","效","斯","院","查","江","型","眼","王","按","格","養","易","置","派","層","片","始","卻","專","狀","育","廠","京","識","適","屬","圓","包","火","住","調","滿","縣","局","照","參","紅","細","引","聽","該","鐵","價","嚴","首","底","液","官","德","隨","病","蘇","失","爾","死","講","配","女","黃","推","顯","談","罪","神","藝","呢","席","含","企","望","密","批","營","項","防","舉","球","英","氧","勢","告","李","台","落","木","幫","輪","破","亞","師","圍","注","遠","字","材","排","供","河","態","封","另","施","減","樹","溶","怎","止","案","言","士","均","武","固","葉","魚","波","視","僅","費","緊","愛","左","章","早","朝","害","續","輕","服","試","食","充","兵","源","判","護","司","足","某","練","差","致","板","田","降","黑","犯","負","擊","范","繼","興","似","餘","堅","曲","輸","修","故","城","夫","夠","送","筆","船","佔","右","財","吃","富","春","職","覺","漢","畫","功","巴","跟","雖","雜","飛","檢","吸","助","昇","陽","互","初","創","抗","考","投","壞","策","古","徑","換","未","跑","留","鋼","曾","端","責","站","簡","述","錢","副","盡","帝","射","草","衝","承","獨","令","限","阿","宣","環","雙","請","超","微","讓","控","州","良","軸","找","否","紀","益","依","優","頂","礎","載","倒","房","突","坐","粉","敵","略","客","袁","冷","勝","絕","析","塊","劑","測","絲","協","訴","念","陳","仍","羅","鹽","友","洋","錯","苦","夜","刑","移","頻","逐","靠","混","母","短","皮","終","聚","汽","村","雲","哪","既","距","衛","停","烈","央","察","燒","迅","境","若","印","洲","刻","括","激","孔","搞","甚","室","待","核","校","散","侵","吧","甲","遊","久","菜","味","舊","模","湖","貨","損","預","阻","毫","普","穩","乙","媽","植","息","擴","銀","語","揮","酒","守","拿","序","紙","醫","缺","雨","嗎","針","劉","啊","急","唱","誤","訓","願","審","附","獲","茶","鮮","糧","斤","孩","脫","硫","肥","善","龍","演","父","漸","血","歡","械","掌","歌","沙","剛","攻","謂","盾","討","晚","粒","亂","燃","矛","乎","殺","藥","寧","魯","貴","鐘","煤","讀","班","伯","香","介","迫","句","豐","培","握","蘭","擔","弦","蛋","沉","假","穿","執","答","樂","誰","順","煙","縮","徵","臉","喜","松","腳","困","異","免","背","星","福","買","染","井","概","慢","怕","磁","倍","祖","皇","促","靜","補","評","翻","肉","踐","尼","衣","寬","揚","棉","希","傷","操","垂","秋","宜","氫","套","督","振","架","亮","末","憲","慶","編","牛","觸","映","雷","銷","詩","座","居","抓","裂","胞","呼","娘","景","威","綠","晶","厚","盟","衡","雞","孫","延","危","膠","屋","鄉","臨","陸","顧","掉","呀","燈","歲","措","束","耐","劇","玉","趙","跳","哥","季","課","凱","胡","額","款","紹","卷","齊","偉","蒸","殖","永","宗","苗","川","爐","岩","弱","零","楊","奏","沿","露","桿","探","滑","鎮","飯","濃","航","懷","趕","庫","奪","伊","靈","稅","途","滅","賽","歸","召","鼓","播","盤","裁","險","康","唯","錄","菌","純","借","糖","蓋","橫","符","私","努","堂","域","槍","潤","幅","哈","竟","熟","蟲","澤","腦","壤","碳","歐","遍","側","寨","敢","徹","慮","斜","薄","庭","納","彈","飼","伸","折","麥","濕","暗","荷","瓦","塞","床","築","惡","戶","訪","塔","奇","透","梁","刀","旋","跡","卡","氯","遇","份","毒","泥","退","洗","擺","灰","彩","賣","耗","夏","擇","忙","銅","獻","硬","予","繁","圈","雪","函","亦","抽","篇","陣","陰","丁","尺","追","堆","雄","迎","泛","爸","樓","避","謀","噸","野","豬","旗","累","偏","典","館","索","秦","脂","潮","爺","豆","忽","托","驚","塑","遺","愈","朱","替","纖","粗","傾","尚","痛","楚","謝","奮","購","磨","君","池","旁","碎","骨","監","捕","弟","暴","割","貫","殊","釋","詞","亡","壁","頓","寶","午","塵","聞","揭","炮","殘","冬","橋","婦","警","綜","招","吳","付","浮","遭","徐","您","搖","谷","贊","箱","隔","訂","男","吹","園","紛","唐","敗","宋","玻","巨","耕","坦","榮","閉","灣","鍵","凡","駐","鍋","救","恩","剝","凝","鹼","齒","截","煉","麻","紡","禁","廢","盛","版","緩","淨","睛","昌","婚","涉","筒","嘴","插","岸","朗","莊","街","藏","姑","貿","腐","奴","啦","慣","乘","夥","恢","勻","紗","扎","辯","耳","彪","臣","億","璃","抵","脈","秀","薩","俄","網","舞","店","噴","縱","寸","汗","掛","洪","賀","閃","柬","爆","烯","津","稻","牆","軟","勇","像","滾","厘","蒙","芳","肯","坡","柱","盪","腿","儀","旅","尾","軋","冰","貢","登","黎","削","鑽","勒","逃","障","氨","郭","峰","幣","港","伏","軌","畝","畢","擦","莫","刺","浪","秘","援","株","健","售","股","島","甘","泡","睡","童","鑄","湯","閥","休","匯","舍","牧","繞","炸","哲","磷","績","朋","淡","尖","啟","陷","柴","呈","徒","顏","淚","稍","忘","泵","藍","拖","洞","授","鏡","辛","壯","鋒","貧","虛","彎","摩","泰","幼","廷","尊","窗","綱","弄","隸","疑","氏","宮","姐","震","瑞","怪","尤","琴","循","描","膜","違","夾","腰","緣","珠","窮","森","枝","竹","溝","催","繩","憶","邦","剩","幸","漿","欄","擁","牙","貯","禮","濾","鈉","紋","罷","拍","咱","喊","袖","埃","勤","罰","焦","潛","伍","墨","欲","縫","姓","刊","飽","仿","獎","鋁","鬼","麗","跨","默","挖","鏈","掃","喝","袋","炭","污","幕","諸","弧","勵","梅","奶","潔","災","舟","鑑","苯","訟","抱","毀","懂","寒","智","埔","寄","屆","躍","渡","挑","丹","艱","貝","碰","拔","爹","戴","碼","夢","芽","熔","赤","漁","哭","敬","顆","奔","鉛","仲","虎","稀","妹","乏","珍","申","桌","遵","允","隆","螺","倉","魏","銳","曉","氮","兼","隱","礙","赫","撥","忠","肅","缸","牽","搶","博","巧","殼","兄","杜","訊","誠","碧","祥","柯","頁","巡","矩","悲","灌","齡","倫","票","尋","桂","鋪","聖","恐","恰","鄭","趣","抬","荒","騰","貼","柔","滴","猛","闊","輛","妻","填","撤","儲","簽","鬧","擾","紫","砂","遞","戲","吊","陶","伐","餵","療","瓶","婆","撫","臂","摸","忍","蝦","蠟","鄰","胸","鞏","擠","偶","棄","槽","勁","乳","鄧","吉","仁","爛","磚","租","烏","艦","伴","瓜","淺","丙","暫","燥","橡","柳","迷","暖","牌","秧","膽","詳","簧","踏","瓷","譜","呆","賓","糊","洛","輝","憤","競","隙","怒","粘","乃","緒","肩","籍","敏","塗","熙","皆","偵","懸","掘","享","糾","醒","狂","鎖","淀","恨","牲","霸","爬","賞","逆","玩","陵","祝","秒","浙","貌","役","彼","悉","鴨","趨","鳳","晨","畜","輩","秩","卵","署","梯","炎","灘","棋","驅","篩","峽","冒","啥","壽","譯","浸","泉","帽","遲","矽","疆","貸","漏","稿","冠","嫩","脅","芯","牢","叛","蝕","奧","鳴","嶺","羊","憑","串","塘","繪","酵","融","盆","錫","廟","籌","凍","輔","攝","襲","筋","拒","僚","旱","鉀","鳥","漆","沈","眉","疏","添","棒","穗","硝","韓","逼","扭","僑","涼","挺","碗","栽","炒","杯","患","餾","勸","豪","遼","勃","鴻","旦","吏","拜","狗","埋","輥","掩","飲","搬","罵","辭","勾","扣","估","蔣","絨","霧","丈","朵","姆","擬","宇","輯","陝","雕","償","蓄","崇","剪","倡","廳","咬","駛","薯","刷","斥","番","賦","奉","佛","澆","漫","曼","扇","鈣","桃","扶","仔","返","俗","虧","腔","鞋","棱","覆","框","悄","叔","撞","騙","勘","旺","沸","孤","吐","孟","渠","屈","疾","妙","惜","仰","狠","脹","諧","拋","黴","桑","崗","嘛","衰","盜","滲","臟","賴","湧","甜","曹","閱","肌","哩","厲","烴","緯","毅","昨","偽","症","煮","嘆","釘","搭","莖","籠","酷","偷","弓","錐","恆","傑","坑","鼻","翼","綸","敘","獄","逮","罐","絡","棚","抑","膨","蔬","寺","驟","穆","冶","枯","冊","屍","凸","紳","坯","犧","焰","轟","欣","晉","瘦","禦","錠","錦","喪","旬","鍛","壟","搜","撲","邀","亭","酯","邁","舒","脆","酶","閒","憂","酚","頑","羽","漲","卸","仗","陪","闢","懲","杭","姚","肚","捉","飄","漂","昆","欺","吾","郎","烷","汁","呵","飾","蕭","雅","郵","遷","燕","撒","姻","赴","宴","煩","債","帳","斑","鈴","旨","醇","董","餅","雛","姿","拌","傅","腹","妥","揉","賢","拆","歪","葡","胺","丟","浩","徽","昂","墊","擋","覽","貪","慰","繳","汪","慌","馮","諾","姜","誼","兇","劣","誣","耀","昏","躺","盈","騎","喬","溪","叢","盧","抹","悶","諮","刮","駕","纜","悟","摘","鉺","擲","頗","幻","柄","惠","慘","佳","仇","臘","窩","滌","劍","瞧","堡","潑","蔥","罩","霍","撈","胎","蒼","濱","倆","捅","湘","砍","霞","邵","萄","瘋","淮","遂","熊","糞","烘","宿","檔","戈","駁","嫂","裕","徙","箭","捐","腸","撐","曬","辨","殿","蓮","攤","攪","醬","屏","疫","哀","蔡","堵","沫","皺","暢","疊","閣","萊","敲","轄","鉤","痕","壩","巷","餓","禍","丘","玄","溜","曰","邏","彭","嘗","卿","妨","艇","吞","韋","怨","矮","歇"]'), Vl = /* @__PURE__ */ JSON.parse('["가격","가끔","가난","가능","가득","가르침","가뭄","가방","가상","가슴","가운데","가을","가이드","가입","가장","가정","가족","가죽","각오","각자","간격","간부","간섭","간장","간접","간판","갈등","갈비","갈색","갈증","감각","감기","감소","감수성","감자","감정","갑자기","강남","강당","강도","강력히","강변","강북","강사","강수량","강아지","강원도","강의","강제","강조","같이","개구리","개나리","개방","개별","개선","개성","개인","객관적","거실","거액","거울","거짓","거품","걱정","건강","건물","건설","건조","건축","걸음","검사","검토","게시판","게임","겨울","견해","결과","결국","결론","결석","결승","결심","결정","결혼","경계","경고","경기","경력","경복궁","경비","경상도","경영","경우","경쟁","경제","경주","경찰","경치","경향","경험","계곡","계단","계란","계산","계속","계약","계절","계층","계획","고객","고구려","고궁","고급","고등학생","고무신","고민","고양이","고장","고전","고집","고춧가루","고통","고향","곡식","골목","골짜기","골프","공간","공개","공격","공군","공급","공기","공동","공무원","공부","공사","공식","공업","공연","공원","공장","공짜","공책","공통","공포","공항","공휴일","과목","과일","과장","과정","과학","관객","관계","관광","관념","관람","관련","관리","관습","관심","관점","관찰","광경","광고","광장","광주","괴로움","굉장히","교과서","교문","교복","교실","교양","교육","교장","교직","교통","교환","교훈","구경","구름","구멍","구별","구분","구석","구성","구속","구역","구입","구청","구체적","국가","국기","국내","국립","국물","국민","국수","국어","국왕","국적","국제","국회","군대","군사","군인","궁극적","권리","권위","권투","귀국","귀신","규정","규칙","균형","그날","그냥","그늘","그러나","그룹","그릇","그림","그제서야","그토록","극복","극히","근거","근교","근래","근로","근무","근본","근원","근육","근처","글씨","글자","금강산","금고","금년","금메달","금액","금연","금요일","금지","긍정적","기간","기관","기념","기능","기독교","기둥","기록","기름","기법","기본","기분","기쁨","기숙사","기술","기억","기업","기온","기운","기원","기적","기준","기침","기혼","기획","긴급","긴장","길이","김밥","김치","김포공항","깍두기","깜빡","깨달음","깨소금","껍질","꼭대기","꽃잎","나들이","나란히","나머지","나물","나침반","나흘","낙엽","난방","날개","날씨","날짜","남녀","남대문","남매","남산","남자","남편","남학생","낭비","낱말","내년","내용","내일","냄비","냄새","냇물","냉동","냉면","냉방","냉장고","넥타이","넷째","노동","노란색","노력","노인","녹음","녹차","녹화","논리","논문","논쟁","놀이","농구","농담","농민","농부","농업","농장","농촌","높이","눈동자","눈물","눈썹","뉴욕","느낌","늑대","능동적","능력","다방","다양성","다음","다이어트","다행","단계","단골","단독","단맛","단순","단어","단위","단점","단체","단추","단편","단풍","달걀","달러","달력","달리","닭고기","담당","담배","담요","담임","답변","답장","당근","당분간","당연히","당장","대규모","대낮","대단히","대답","대도시","대략","대량","대륙","대문","대부분","대신","대응","대장","대전","대접","대중","대책","대출","대충","대통령","대학","대한민국","대합실","대형","덩어리","데이트","도대체","도덕","도둑","도망","도서관","도심","도움","도입","도자기","도저히","도전","도중","도착","독감","독립","독서","독일","독창적","동화책","뒷모습","뒷산","딸아이","마누라","마늘","마당","마라톤","마련","마무리","마사지","마약","마요네즈","마을","마음","마이크","마중","마지막","마찬가지","마찰","마흔","막걸리","막내","막상","만남","만두","만세","만약","만일","만점","만족","만화","많이","말기","말씀","말투","맘대로","망원경","매년","매달","매력","매번","매스컴","매일","매장","맥주","먹이","먼저","먼지","멀리","메일","며느리","며칠","면담","멸치","명단","명령","명예","명의","명절","명칭","명함","모금","모니터","모델","모든","모범","모습","모양","모임","모조리","모집","모퉁이","목걸이","목록","목사","목소리","목숨","목적","목표","몰래","몸매","몸무게","몸살","몸속","몸짓","몸통","몹시","무관심","무궁화","무더위","무덤","무릎","무슨","무엇","무역","무용","무조건","무지개","무척","문구","문득","문법","문서","문제","문학","문화","물가","물건","물결","물고기","물론","물리학","물음","물질","물체","미국","미디어","미사일","미술","미역","미용실","미움","미인","미팅","미혼","민간","민족","민주","믿음","밀가루","밀리미터","밑바닥","바가지","바구니","바나나","바늘","바닥","바닷가","바람","바이러스","바탕","박물관","박사","박수","반대","반드시","반말","반발","반성","반응","반장","반죽","반지","반찬","받침","발가락","발걸음","발견","발달","발레","발목","발바닥","발생","발음","발자국","발전","발톱","발표","밤하늘","밥그릇","밥맛","밥상","밥솥","방금","방면","방문","방바닥","방법","방송","방식","방안","방울","방지","방학","방해","방향","배경","배꼽","배달","배드민턴","백두산","백색","백성","백인","백제","백화점","버릇","버섯","버튼","번개","번역","번지","번호","벌금","벌레","벌써","범위","범인","범죄","법률","법원","법적","법칙","베이징","벨트","변경","변동","변명","변신","변호사","변화","별도","별명","별일","병실","병아리","병원","보관","보너스","보라색","보람","보름","보상","보안","보자기","보장","보전","보존","보통","보편적","보험","복도","복사","복숭아","복습","볶음","본격적","본래","본부","본사","본성","본인","본질","볼펜","봉사","봉지","봉투","부근","부끄러움","부담","부동산","부문","부분","부산","부상","부엌","부인","부작용","부장","부정","부족","부지런히","부친","부탁","부품","부회장","북부","북한","분노","분량","분리","분명","분석","분야","분위기","분필","분홍색","불고기","불과","불교","불꽃","불만","불법","불빛","불안","불이익","불행","브랜드","비극","비난","비닐","비둘기","비디오","비로소","비만","비명","비밀","비바람","비빔밥","비상","비용","비율","비중","비타민","비판","빌딩","빗물","빗방울","빗줄기","빛깔","빨간색","빨래","빨리","사건","사계절","사나이","사냥","사람","사랑","사립","사모님","사물","사방","사상","사생활","사설","사슴","사실","사업","사용","사월","사장","사전","사진","사촌","사춘기","사탕","사투리","사흘","산길","산부인과","산업","산책","살림","살인","살짝","삼계탕","삼국","삼십","삼월","삼촌","상관","상금","상대","상류","상반기","상상","상식","상업","상인","상자","상점","상처","상추","상태","상표","상품","상황","새벽","색깔","색연필","생각","생명","생물","생방송","생산","생선","생신","생일","생활","서랍","서른","서명","서민","서비스","서양","서울","서적","서점","서쪽","서클","석사","석유","선거","선물","선배","선생","선수","선원","선장","선전","선택","선풍기","설거지","설날","설렁탕","설명","설문","설사","설악산","설치","설탕","섭씨","성공","성당","성명","성별","성인","성장","성적","성질","성함","세금","세미나","세상","세월","세종대왕","세탁","센터","센티미터","셋째","소규모","소극적","소금","소나기","소년","소득","소망","소문","소설","소속","소아과","소용","소원","소음","소중히","소지품","소질","소풍","소형","속담","속도","속옷","손가락","손길","손녀","손님","손등","손목","손뼉","손실","손질","손톱","손해","솔직히","솜씨","송아지","송이","송편","쇠고기","쇼핑","수건","수년","수단","수돗물","수동적","수면","수명","수박","수상","수석","수술","수시로","수업","수염","수영","수입","수준","수집","수출","수컷","수필","수학","수험생","수화기","숙녀","숙소","숙제","순간","순서","순수","순식간","순위","숟가락","술병","술집","숫자","스님","스물","스스로","스승","스웨터","스위치","스케이트","스튜디오","스트레스","스포츠","슬쩍","슬픔","습관","습기","승객","승리","승부","승용차","승진","시각","시간","시골","시금치","시나리오","시댁","시리즈","시멘트","시민","시부모","시선","시설","시스템","시아버지","시어머니","시월","시인","시일","시작","시장","시절","시점","시중","시즌","시집","시청","시합","시험","식구","식기","식당","식량","식료품","식물","식빵","식사","식생활","식초","식탁","식품","신고","신규","신념","신문","신발","신비","신사","신세","신용","신제품","신청","신체","신화","실감","실내","실력","실례","실망","실수","실습","실시","실장","실정","실질적","실천","실체","실컷","실태","실패","실험","실현","심리","심부름","심사","심장","심정","심판","쌍둥이","씨름","씨앗","아가씨","아나운서","아드님","아들","아쉬움","아스팔트","아시아","아울러","아저씨","아줌마","아직","아침","아파트","아프리카","아픔","아홉","아흔","악기","악몽","악수","안개","안경","안과","안내","안녕","안동","안방","안부","안주","알루미늄","알코올","암시","암컷","압력","앞날","앞문","애인","애정","액수","앨범","야간","야단","야옹","약간","약국","약속","약수","약점","약품","약혼녀","양념","양력","양말","양배추","양주","양파","어둠","어려움","어른","어젯밤","어쨌든","어쩌다가","어쩐지","언니","언덕","언론","언어","얼굴","얼른","얼음","얼핏","엄마","업무","업종","업체","엉덩이","엉망","엉터리","엊그제","에너지","에어컨","엔진","여건","여고생","여관","여군","여권","여대생","여덟","여동생","여든","여론","여름","여섯","여성","여왕","여인","여전히","여직원","여학생","여행","역사","역시","역할","연결","연구","연극","연기","연락","연설","연세","연속","연습","연애","연예인","연인","연장","연주","연출","연필","연합","연휴","열기","열매","열쇠","열심히","열정","열차","열흘","염려","엽서","영국","영남","영상","영양","영역","영웅","영원히","영하","영향","영혼","영화","옆구리","옆방","옆집","예감","예금","예방","예산","예상","예선","예술","예습","예식장","예약","예전","예절","예정","예컨대","옛날","오늘","오락","오랫동안","오렌지","오로지","오른발","오븐","오십","오염","오월","오전","오직","오징어","오페라","오피스텔","오히려","옥상","옥수수","온갖","온라인","온몸","온종일","온통","올가을","올림픽","올해","옷차림","와이셔츠","와인","완성","완전","왕비","왕자","왜냐하면","왠지","외갓집","외국","외로움","외삼촌","외출","외침","외할머니","왼발","왼손","왼쪽","요금","요일","요즘","요청","용기","용서","용어","우산","우선","우승","우연히","우정","우체국","우편","운동","운명","운반","운전","운행","울산","울음","움직임","웃어른","웃음","워낙","원고","원래","원서","원숭이","원인","원장","원피스","월급","월드컵","월세","월요일","웨이터","위반","위법","위성","위원","위험","위협","윗사람","유난히","유럽","유명","유물","유산","유적","유치원","유학","유행","유형","육군","육상","육십","육체","은행","음력","음료","음반","음성","음식","음악","음주","의견","의논","의문","의복","의식","의심","의외로","의욕","의원","의학","이것","이곳","이념","이놈","이달","이대로","이동","이렇게","이력서","이론적","이름","이민","이발소","이별","이불","이빨","이상","이성","이슬","이야기","이용","이웃","이월","이윽고","이익","이전","이중","이튿날","이틀","이혼","인간","인격","인공","인구","인근","인기","인도","인류","인물","인생","인쇄","인연","인원","인재","인종","인천","인체","인터넷","인하","인형","일곱","일기","일단","일대","일등","일반","일본","일부","일상","일생","일손","일요일","일월","일정","일종","일주일","일찍","일체","일치","일행","일회용","임금","임무","입대","입력","입맛","입사","입술","입시","입원","입장","입학","자가용","자격","자극","자동","자랑","자부심","자식","자신","자연","자원","자율","자전거","자정","자존심","자판","작가","작년","작성","작업","작용","작은딸","작품","잔디","잔뜩","잔치","잘못","잠깐","잠수함","잠시","잠옷","잠자리","잡지","장관","장군","장기간","장래","장례","장르","장마","장면","장모","장미","장비","장사","장소","장식","장애인","장인","장점","장차","장학금","재능","재빨리","재산","재생","재작년","재정","재채기","재판","재학","재활용","저것","저고리","저곳","저녁","저런","저렇게","저번","저울","저절로","저축","적극","적당히","적성","적용","적응","전개","전공","전기","전달","전라도","전망","전문","전반","전부","전세","전시","전용","전자","전쟁","전주","전철","전체","전통","전혀","전후","절대","절망","절반","절약","절차","점검","점수","점심","점원","점점","점차","접근","접시","접촉","젓가락","정거장","정도","정류장","정리","정말","정면","정문","정반대","정보","정부","정비","정상","정성","정오","정원","정장","정지","정치","정확히","제공","제과점","제대로","제목","제발","제법","제삿날","제안","제일","제작","제주도","제출","제품","제한","조각","조건","조금","조깅","조명","조미료","조상","조선","조용히","조절","조정","조직","존댓말","존재","졸업","졸음","종교","종로","종류","종소리","종업원","종종","종합","좌석","죄인","주관적","주름","주말","주머니","주먹","주문","주민","주방","주변","주식","주인","주일","주장","주전자","주택","준비","줄거리","줄기","줄무늬","중간","중계방송","중국","중년","중단","중독","중반","중부","중세","중소기업","중순","중앙","중요","중학교","즉석","즉시","즐거움","증가","증거","증권","증상","증세","지각","지갑","지경","지극히","지금","지급","지능","지름길","지리산","지방","지붕","지식","지역","지우개","지원","지적","지점","지진","지출","직선","직업","직원","직장","진급","진동","진로","진료","진리","진짜","진찰","진출","진통","진행","질문","질병","질서","짐작","집단","집안","집중","짜증","찌꺼기","차남","차라리","차량","차림","차별","차선","차츰","착각","찬물","찬성","참가","참기름","참새","참석","참여","참외","참조","찻잔","창가","창고","창구","창문","창밖","창작","창조","채널","채점","책가방","책방","책상","책임","챔피언","처벌","처음","천국","천둥","천장","천재","천천히","철도","철저히","철학","첫날","첫째","청년","청바지","청소","청춘","체계","체력","체온","체육","체중","체험","초등학생","초반","초밥","초상화","초순","초여름","초원","초저녁","초점","초청","초콜릿","촛불","총각","총리","총장","촬영","최근","최상","최선","최신","최악","최종","추석","추억","추진","추천","추측","축구","축소","축제","축하","출근","출발","출산","출신","출연","출입","출장","출판","충격","충고","충돌","충분히","충청도","취업","취직","취향","치약","친구","친척","칠십","칠월","칠판","침대","침묵","침실","칫솔","칭찬","카메라","카운터","칼국수","캐릭터","캠퍼스","캠페인","커튼","컨디션","컬러","컴퓨터","코끼리","코미디","콘서트","콜라","콤플렉스","콩나물","쾌감","쿠데타","크림","큰길","큰딸","큰소리","큰아들","큰어머니","큰일","큰절","클래식","클럽","킬로","타입","타자기","탁구","탁자","탄생","태권도","태양","태풍","택시","탤런트","터널","터미널","테니스","테스트","테이블","텔레비전","토론","토마토","토요일","통계","통과","통로","통신","통역","통일","통장","통제","통증","통합","통화","퇴근","퇴원","퇴직금","튀김","트럭","특급","특별","특성","특수","특징","특히","튼튼히","티셔츠","파란색","파일","파출소","판결","판단","판매","판사","팔십","팔월","팝송","패션","팩스","팩시밀리","팬티","퍼센트","페인트","편견","편의","편지","편히","평가","평균","평생","평소","평양","평일","평화","포스터","포인트","포장","포함","표면","표정","표준","표현","품목","품질","풍경","풍속","풍습","프랑스","프린터","플라스틱","피곤","피망","피아노","필름","필수","필요","필자","필통","핑계","하느님","하늘","하드웨어","하룻밤","하반기","하숙집","하순","하여튼","하지만","하천","하품","하필","학과","학교","학급","학기","학년","학력","학번","학부모","학비","학생","학술","학습","학용품","학원","학위","학자","학점","한계","한글","한꺼번에","한낮","한눈","한동안","한때","한라산","한마디","한문","한번","한복","한식","한여름","한쪽","할머니","할아버지","할인","함께","함부로","합격","합리적","항공","항구","항상","항의","해결","해군","해답","해당","해물","해석","해설","해수욕장","해안","핵심","핸드백","햄버거","햇볕","햇살","행동","행복","행사","행운","행위","향기","향상","향수","허락","허용","헬기","현관","현금","현대","현상","현실","현장","현재","현지","혈액","협력","형부","형사","형수","형식","형제","형태","형편","혜택","호기심","호남","호랑이","호박","호텔","호흡","혹시","홀로","홈페이지","홍보","홍수","홍차","화면","화분","화살","화요일","화장","화학","확보","확인","확장","확정","환갑","환경","환영","환율","환자","활기","활동","활발히","활용","활짝","회견","회관","회복","회색","회원","회장","회전","횟수","횡단보도","효율적","후반","후춧가루","훈련","훨씬","휴식","휴일","흉내","흐름","흑백","흑인","흔적","흔히","흥미","흥분","희곡","희망","희생","흰색","힘껏"]'), Gl = /* @__PURE__ */ JSON.parse('["abaisser","abandon","abdiquer","abeille","abolir","aborder","aboutir","aboyer","abrasif","abreuver","abriter","abroger","abrupt","absence","absolu","absurde","abusif","abyssal","académie","acajou","acarien","accabler","accepter","acclamer","accolade","accroche","accuser","acerbe","achat","acheter","aciduler","acier","acompte","acquérir","acronyme","acteur","actif","actuel","adepte","adéquat","adhésif","adjectif","adjuger","admettre","admirer","adopter","adorer","adoucir","adresse","adroit","adulte","adverbe","aérer","aéronef","affaire","affecter","affiche","affreux","affubler","agacer","agencer","agile","agiter","agrafer","agréable","agrume","aider","aiguille","ailier","aimable","aisance","ajouter","ajuster","alarmer","alchimie","alerte","algèbre","algue","aliéner","aliment","alléger","alliage","allouer","allumer","alourdir","alpaga","altesse","alvéole","amateur","ambigu","ambre","aménager","amertume","amidon","amiral","amorcer","amour","amovible","amphibie","ampleur","amusant","analyse","anaphore","anarchie","anatomie","ancien","anéantir","angle","angoisse","anguleux","animal","annexer","annonce","annuel","anodin","anomalie","anonyme","anormal","antenne","antidote","anxieux","apaiser","apéritif","aplanir","apologie","appareil","appeler","apporter","appuyer","aquarium","aqueduc","arbitre","arbuste","ardeur","ardoise","argent","arlequin","armature","armement","armoire","armure","arpenter","arracher","arriver","arroser","arsenic","artériel","article","aspect","asphalte","aspirer","assaut","asservir","assiette","associer","assurer","asticot","astre","astuce","atelier","atome","atrium","atroce","attaque","attentif","attirer","attraper","aubaine","auberge","audace","audible","augurer","aurore","automne","autruche","avaler","avancer","avarice","avenir","averse","aveugle","aviateur","avide","avion","aviser","avoine","avouer","avril","axial","axiome","badge","bafouer","bagage","baguette","baignade","balancer","balcon","baleine","balisage","bambin","bancaire","bandage","banlieue","bannière","banquier","barbier","baril","baron","barque","barrage","bassin","bastion","bataille","bateau","batterie","baudrier","bavarder","belette","bélier","belote","bénéfice","berceau","berger","berline","bermuda","besace","besogne","bétail","beurre","biberon","bicycle","bidule","bijou","bilan","bilingue","billard","binaire","biologie","biopsie","biotype","biscuit","bison","bistouri","bitume","bizarre","blafard","blague","blanchir","blessant","blinder","blond","bloquer","blouson","bobard","bobine","boire","boiser","bolide","bonbon","bondir","bonheur","bonifier","bonus","bordure","borne","botte","boucle","boueux","bougie","boulon","bouquin","bourse","boussole","boutique","boxeur","branche","brasier","brave","brebis","brèche","breuvage","bricoler","brigade","brillant","brioche","brique","brochure","broder","bronzer","brousse","broyeur","brume","brusque","brutal","bruyant","buffle","buisson","bulletin","bureau","burin","bustier","butiner","butoir","buvable","buvette","cabanon","cabine","cachette","cadeau","cadre","caféine","caillou","caisson","calculer","calepin","calibre","calmer","calomnie","calvaire","camarade","caméra","camion","campagne","canal","caneton","canon","cantine","canular","capable","caporal","caprice","capsule","capter","capuche","carabine","carbone","caresser","caribou","carnage","carotte","carreau","carton","cascade","casier","casque","cassure","causer","caution","cavalier","caverne","caviar","cédille","ceinture","céleste","cellule","cendrier","censurer","central","cercle","cérébral","cerise","cerner","cerveau","cesser","chagrin","chaise","chaleur","chambre","chance","chapitre","charbon","chasseur","chaton","chausson","chavirer","chemise","chenille","chéquier","chercher","cheval","chien","chiffre","chignon","chimère","chiot","chlorure","chocolat","choisir","chose","chouette","chrome","chute","cigare","cigogne","cimenter","cinéma","cintrer","circuler","cirer","cirque","citerne","citoyen","citron","civil","clairon","clameur","claquer","classe","clavier","client","cligner","climat","clivage","cloche","clonage","cloporte","cobalt","cobra","cocasse","cocotier","coder","codifier","coffre","cogner","cohésion","coiffer","coincer","colère","colibri","colline","colmater","colonel","combat","comédie","commande","compact","concert","conduire","confier","congeler","connoter","consonne","contact","convexe","copain","copie","corail","corbeau","cordage","corniche","corpus","correct","cortège","cosmique","costume","coton","coude","coupure","courage","couteau","couvrir","coyote","crabe","crainte","cravate","crayon","créature","créditer","crémeux","creuser","crevette","cribler","crier","cristal","critère","croire","croquer","crotale","crucial","cruel","crypter","cubique","cueillir","cuillère","cuisine","cuivre","culminer","cultiver","cumuler","cupide","curatif","curseur","cyanure","cycle","cylindre","cynique","daigner","damier","danger","danseur","dauphin","débattre","débiter","déborder","débrider","débutant","décaler","décembre","déchirer","décider","déclarer","décorer","décrire","décupler","dédale","déductif","déesse","défensif","défiler","défrayer","dégager","dégivrer","déglutir","dégrafer","déjeuner","délice","déloger","demander","demeurer","démolir","dénicher","dénouer","dentelle","dénuder","départ","dépenser","déphaser","déplacer","déposer","déranger","dérober","désastre","descente","désert","désigner","désobéir","dessiner","destrier","détacher","détester","détourer","détresse","devancer","devenir","deviner","devoir","diable","dialogue","diamant","dicter","différer","digérer","digital","digne","diluer","dimanche","diminuer","dioxyde","directif","diriger","discuter","disposer","dissiper","distance","divertir","diviser","docile","docteur","dogme","doigt","domaine","domicile","dompter","donateur","donjon","donner","dopamine","dortoir","dorure","dosage","doseur","dossier","dotation","douanier","double","douceur","douter","doyen","dragon","draper","dresser","dribbler","droiture","duperie","duplexe","durable","durcir","dynastie","éblouir","écarter","écharpe","échelle","éclairer","éclipse","éclore","écluse","école","économie","écorce","écouter","écraser","écrémer","écrivain","écrou","écume","écureuil","édifier","éduquer","effacer","effectif","effigie","effort","effrayer","effusion","égaliser","égarer","éjecter","élaborer","élargir","électron","élégant","éléphant","élève","éligible","élitisme","éloge","élucider","éluder","emballer","embellir","embryon","émeraude","émission","emmener","émotion","émouvoir","empereur","employer","emporter","emprise","émulsion","encadrer","enchère","enclave","encoche","endiguer","endosser","endroit","enduire","énergie","enfance","enfermer","enfouir","engager","engin","englober","énigme","enjamber","enjeu","enlever","ennemi","ennuyeux","enrichir","enrobage","enseigne","entasser","entendre","entier","entourer","entraver","énumérer","envahir","enviable","envoyer","enzyme","éolien","épaissir","épargne","épatant","épaule","épicerie","épidémie","épier","épilogue","épine","épisode","épitaphe","époque","épreuve","éprouver","épuisant","équerre","équipe","ériger","érosion","erreur","éruption","escalier","espadon","espèce","espiègle","espoir","esprit","esquiver","essayer","essence","essieu","essorer","estime","estomac","estrade","étagère","étaler","étanche","étatique","éteindre","étendoir","éternel","éthanol","éthique","ethnie","étirer","étoffer","étoile","étonnant","étourdir","étrange","étroit","étude","euphorie","évaluer","évasion","éventail","évidence","éviter","évolutif","évoquer","exact","exagérer","exaucer","exceller","excitant","exclusif","excuse","exécuter","exemple","exercer","exhaler","exhorter","exigence","exiler","exister","exotique","expédier","explorer","exposer","exprimer","exquis","extensif","extraire","exulter","fable","fabuleux","facette","facile","facture","faiblir","falaise","fameux","famille","farceur","farfelu","farine","farouche","fasciner","fatal","fatigue","faucon","fautif","faveur","favori","fébrile","féconder","fédérer","félin","femme","fémur","fendoir","féodal","fermer","féroce","ferveur","festival","feuille","feutre","février","fiasco","ficeler","fictif","fidèle","figure","filature","filetage","filière","filleul","filmer","filou","filtrer","financer","finir","fiole","firme","fissure","fixer","flairer","flamme","flasque","flatteur","fléau","flèche","fleur","flexion","flocon","flore","fluctuer","fluide","fluvial","folie","fonderie","fongible","fontaine","forcer","forgeron","formuler","fortune","fossile","foudre","fougère","fouiller","foulure","fourmi","fragile","fraise","franchir","frapper","frayeur","frégate","freiner","frelon","frémir","frénésie","frère","friable","friction","frisson","frivole","froid","fromage","frontal","frotter","fruit","fugitif","fuite","fureur","furieux","furtif","fusion","futur","gagner","galaxie","galerie","gambader","garantir","gardien","garnir","garrigue","gazelle","gazon","géant","gélatine","gélule","gendarme","général","génie","genou","gentil","géologie","géomètre","géranium","germe","gestuel","geyser","gibier","gicler","girafe","givre","glace","glaive","glisser","globe","gloire","glorieux","golfeur","gomme","gonfler","gorge","gorille","goudron","gouffre","goulot","goupille","gourmand","goutte","graduel","graffiti","graine","grand","grappin","gratuit","gravir","grenat","griffure","griller","grimper","grogner","gronder","grotte","groupe","gruger","grutier","gruyère","guépard","guerrier","guide","guimauve","guitare","gustatif","gymnaste","gyrostat","habitude","hachoir","halte","hameau","hangar","hanneton","haricot","harmonie","harpon","hasard","hélium","hématome","herbe","hérisson","hermine","héron","hésiter","heureux","hiberner","hibou","hilarant","histoire","hiver","homard","hommage","homogène","honneur","honorer","honteux","horde","horizon","horloge","hormone","horrible","houleux","housse","hublot","huileux","humain","humble","humide","humour","hurler","hydromel","hygiène","hymne","hypnose","idylle","ignorer","iguane","illicite","illusion","image","imbiber","imiter","immense","immobile","immuable","impact","impérial","implorer","imposer","imprimer","imputer","incarner","incendie","incident","incliner","incolore","indexer","indice","inductif","inédit","ineptie","inexact","infini","infliger","informer","infusion","ingérer","inhaler","inhiber","injecter","injure","innocent","inoculer","inonder","inscrire","insecte","insigne","insolite","inspirer","instinct","insulter","intact","intense","intime","intrigue","intuitif","inutile","invasion","inventer","inviter","invoquer","ironique","irradier","irréel","irriter","isoler","ivoire","ivresse","jaguar","jaillir","jambe","janvier","jardin","jauger","jaune","javelot","jetable","jeton","jeudi","jeunesse","joindre","joncher","jongler","joueur","jouissif","journal","jovial","joyau","joyeux","jubiler","jugement","junior","jupon","juriste","justice","juteux","juvénile","kayak","kimono","kiosque","label","labial","labourer","lacérer","lactose","lagune","laine","laisser","laitier","lambeau","lamelle","lampe","lanceur","langage","lanterne","lapin","largeur","larme","laurier","lavabo","lavoir","lecture","légal","léger","légume","lessive","lettre","levier","lexique","lézard","liasse","libérer","libre","licence","licorne","liège","lièvre","ligature","ligoter","ligue","limer","limite","limonade","limpide","linéaire","lingot","lionceau","liquide","lisière","lister","lithium","litige","littoral","livreur","logique","lointain","loisir","lombric","loterie","louer","lourd","loutre","louve","loyal","lubie","lucide","lucratif","lueur","lugubre","luisant","lumière","lunaire","lundi","luron","lutter","luxueux","machine","magasin","magenta","magique","maigre","maillon","maintien","mairie","maison","majorer","malaxer","maléfice","malheur","malice","mallette","mammouth","mandater","maniable","manquant","manteau","manuel","marathon","marbre","marchand","mardi","maritime","marqueur","marron","marteler","mascotte","massif","matériel","matière","matraque","maudire","maussade","mauve","maximal","méchant","méconnu","médaille","médecin","méditer","méduse","meilleur","mélange","mélodie","membre","mémoire","menacer","mener","menhir","mensonge","mentor","mercredi","mérite","merle","messager","mesure","métal","météore","méthode","métier","meuble","miauler","microbe","miette","mignon","migrer","milieu","million","mimique","mince","minéral","minimal","minorer","minute","miracle","miroiter","missile","mixte","mobile","moderne","moelleux","mondial","moniteur","monnaie","monotone","monstre","montagne","monument","moqueur","morceau","morsure","mortier","moteur","motif","mouche","moufle","moulin","mousson","mouton","mouvant","multiple","munition","muraille","murène","murmure","muscle","muséum","musicien","mutation","muter","mutuel","myriade","myrtille","mystère","mythique","nageur","nappe","narquois","narrer","natation","nation","nature","naufrage","nautique","navire","nébuleux","nectar","néfaste","négation","négliger","négocier","neige","nerveux","nettoyer","neurone","neutron","neveu","niche","nickel","nitrate","niveau","noble","nocif","nocturne","noirceur","noisette","nomade","nombreux","nommer","normatif","notable","notifier","notoire","nourrir","nouveau","novateur","novembre","novice","nuage","nuancer","nuire","nuisible","numéro","nuptial","nuque","nutritif","obéir","objectif","obliger","obscur","observer","obstacle","obtenir","obturer","occasion","occuper","océan","octobre","octroyer","octupler","oculaire","odeur","odorant","offenser","officier","offrir","ogive","oiseau","oisillon","olfactif","olivier","ombrage","omettre","onctueux","onduler","onéreux","onirique","opale","opaque","opérer","opinion","opportun","opprimer","opter","optique","orageux","orange","orbite","ordonner","oreille","organe","orgueil","orifice","ornement","orque","ortie","osciller","osmose","ossature","otarie","ouragan","ourson","outil","outrager","ouvrage","ovation","oxyde","oxygène","ozone","paisible","palace","palmarès","palourde","palper","panache","panda","pangolin","paniquer","panneau","panorama","pantalon","papaye","papier","papoter","papyrus","paradoxe","parcelle","paresse","parfumer","parler","parole","parrain","parsemer","partager","parure","parvenir","passion","pastèque","paternel","patience","patron","pavillon","pavoiser","payer","paysage","peigne","peintre","pelage","pélican","pelle","pelouse","peluche","pendule","pénétrer","pénible","pensif","pénurie","pépite","péplum","perdrix","perforer","période","permuter","perplexe","persil","perte","peser","pétale","petit","pétrir","peuple","pharaon","phobie","phoque","photon","phrase","physique","piano","pictural","pièce","pierre","pieuvre","pilote","pinceau","pipette","piquer","pirogue","piscine","piston","pivoter","pixel","pizza","placard","plafond","plaisir","planer","plaque","plastron","plateau","pleurer","plexus","pliage","plomb","plonger","pluie","plumage","pochette","poésie","poète","pointe","poirier","poisson","poivre","polaire","policier","pollen","polygone","pommade","pompier","ponctuel","pondérer","poney","portique","position","posséder","posture","potager","poteau","potion","pouce","poulain","poumon","pourpre","poussin","pouvoir","prairie","pratique","précieux","prédire","préfixe","prélude","prénom","présence","prétexte","prévoir","primitif","prince","prison","priver","problème","procéder","prodige","profond","progrès","proie","projeter","prologue","promener","propre","prospère","protéger","prouesse","proverbe","prudence","pruneau","psychose","public","puceron","puiser","pulpe","pulsar","punaise","punitif","pupitre","purifier","puzzle","pyramide","quasar","querelle","question","quiétude","quitter","quotient","racine","raconter","radieux","ragondin","raideur","raisin","ralentir","rallonge","ramasser","rapide","rasage","ratisser","ravager","ravin","rayonner","réactif","réagir","réaliser","réanimer","recevoir","réciter","réclamer","récolter","recruter","reculer","recycler","rédiger","redouter","refaire","réflexe","réformer","refrain","refuge","régalien","région","réglage","régulier","réitérer","rejeter","rejouer","relatif","relever","relief","remarque","remède","remise","remonter","remplir","remuer","renard","renfort","renifler","renoncer","rentrer","renvoi","replier","reporter","reprise","reptile","requin","réserve","résineux","résoudre","respect","rester","résultat","rétablir","retenir","réticule","retomber","retracer","réunion","réussir","revanche","revivre","révolte","révulsif","richesse","rideau","rieur","rigide","rigoler","rincer","riposter","risible","risque","rituel","rival","rivière","rocheux","romance","rompre","ronce","rondin","roseau","rosier","rotatif","rotor","rotule","rouge","rouille","rouleau","routine","royaume","ruban","rubis","ruche","ruelle","rugueux","ruiner","ruisseau","ruser","rustique","rythme","sabler","saboter","sabre","sacoche","safari","sagesse","saisir","salade","salive","salon","saluer","samedi","sanction","sanglier","sarcasme","sardine","saturer","saugrenu","saumon","sauter","sauvage","savant","savonner","scalpel","scandale","scélérat","scénario","sceptre","schéma","science","scinder","score","scrutin","sculpter","séance","sécable","sécher","secouer","sécréter","sédatif","séduire","seigneur","séjour","sélectif","semaine","sembler","semence","séminal","sénateur","sensible","sentence","séparer","séquence","serein","sergent","sérieux","serrure","sérum","service","sésame","sévir","sevrage","sextuple","sidéral","siècle","siéger","siffler","sigle","signal","silence","silicium","simple","sincère","sinistre","siphon","sirop","sismique","situer","skier","social","socle","sodium","soigneux","soldat","soleil","solitude","soluble","sombre","sommeil","somnoler","sonde","songeur","sonnette","sonore","sorcier","sortir","sosie","sottise","soucieux","soudure","souffle","soulever","soupape","source","soutirer","souvenir","spacieux","spatial","spécial","sphère","spiral","stable","station","sternum","stimulus","stipuler","strict","studieux","stupeur","styliste","sublime","substrat","subtil","subvenir","succès","sucre","suffixe","suggérer","suiveur","sulfate","superbe","supplier","surface","suricate","surmener","surprise","sursaut","survie","suspect","syllabe","symbole","symétrie","synapse","syntaxe","système","tabac","tablier","tactile","tailler","talent","talisman","talonner","tambour","tamiser","tangible","tapis","taquiner","tarder","tarif","tartine","tasse","tatami","tatouage","taupe","taureau","taxer","témoin","temporel","tenaille","tendre","teneur","tenir","tension","terminer","terne","terrible","tétine","texte","thème","théorie","thérapie","thorax","tibia","tiède","timide","tirelire","tiroir","tissu","titane","titre","tituber","toboggan","tolérant","tomate","tonique","tonneau","toponyme","torche","tordre","tornade","torpille","torrent","torse","tortue","totem","toucher","tournage","tousser","toxine","traction","trafic","tragique","trahir","train","trancher","travail","trèfle","tremper","trésor","treuil","triage","tribunal","tricoter","trilogie","triomphe","tripler","triturer","trivial","trombone","tronc","tropical","troupeau","tuile","tulipe","tumulte","tunnel","turbine","tuteur","tutoyer","tuyau","tympan","typhon","typique","tyran","ubuesque","ultime","ultrason","unanime","unifier","union","unique","unitaire","univers","uranium","urbain","urticant","usage","usine","usuel","usure","utile","utopie","vacarme","vaccin","vagabond","vague","vaillant","vaincre","vaisseau","valable","valise","vallon","valve","vampire","vanille","vapeur","varier","vaseux","vassal","vaste","vecteur","vedette","végétal","véhicule","veinard","véloce","vendredi","vénérer","venger","venimeux","ventouse","verdure","vérin","vernir","verrou","verser","vertu","veston","vétéran","vétuste","vexant","vexer","viaduc","viande","victoire","vidange","vidéo","vignette","vigueur","vilain","village","vinaigre","violon","vipère","virement","virtuose","virus","visage","viseur","vision","visqueux","visuel","vital","vitesse","viticole","vitrine","vivace","vivipare","vocation","voguer","voile","voisin","voiture","volaille","volcan","voltiger","volume","vorace","vortex","voter","vouloir","voyage","voyelle","wagon","xénon","yacht","zèbre","zénith","zeste","zoologie"]'), Wl = /* @__PURE__ */ JSON.parse('["abaco","abbaglio","abbinato","abete","abisso","abolire","abrasivo","abrogato","accadere","accenno","accusato","acetone","achille","acido","acqua","acre","acrilico","acrobata","acuto","adagio","addebito","addome","adeguato","aderire","adipe","adottare","adulare","affabile","affetto","affisso","affranto","aforisma","afoso","africano","agave","agente","agevole","aggancio","agire","agitare","agonismo","agricolo","agrumeto","aguzzo","alabarda","alato","albatro","alberato","albo","albume","alce","alcolico","alettone","alfa","algebra","aliante","alibi","alimento","allagato","allegro","allievo","allodola","allusivo","almeno","alogeno","alpaca","alpestre","altalena","alterno","alticcio","altrove","alunno","alveolo","alzare","amalgama","amanita","amarena","ambito","ambrato","ameba","america","ametista","amico","ammasso","ammenda","ammirare","ammonito","amore","ampio","ampliare","amuleto","anacardo","anagrafe","analista","anarchia","anatra","anca","ancella","ancora","andare","andrea","anello","angelo","angolare","angusto","anima","annegare","annidato","anno","annuncio","anonimo","anticipo","anzi","apatico","apertura","apode","apparire","appetito","appoggio","approdo","appunto","aprile","arabica","arachide","aragosta","araldica","arancio","aratura","arazzo","arbitro","archivio","ardito","arenile","argento","argine","arguto","aria","armonia","arnese","arredato","arringa","arrosto","arsenico","arso","artefice","arzillo","asciutto","ascolto","asepsi","asettico","asfalto","asino","asola","aspirato","aspro","assaggio","asse","assoluto","assurdo","asta","astenuto","astice","astratto","atavico","ateismo","atomico","atono","attesa","attivare","attorno","attrito","attuale","ausilio","austria","autista","autonomo","autunno","avanzato","avere","avvenire","avviso","avvolgere","azione","azoto","azzimo","azzurro","babele","baccano","bacino","baco","badessa","badilata","bagnato","baita","balcone","baldo","balena","ballata","balzano","bambino","bandire","baraonda","barbaro","barca","baritono","barlume","barocco","basilico","basso","batosta","battuto","baule","bava","bavosa","becco","beffa","belgio","belva","benda","benevole","benigno","benzina","bere","berlina","beta","bibita","bici","bidone","bifido","biga","bilancia","bimbo","binocolo","biologo","bipede","bipolare","birbante","birra","biscotto","bisesto","bisnonno","bisonte","bisturi","bizzarro","blando","blatta","bollito","bonifico","bordo","bosco","botanico","bottino","bozzolo","braccio","bradipo","brama","branca","bravura","bretella","brevetto","brezza","briglia","brillante","brindare","broccolo","brodo","bronzina","brullo","bruno","bubbone","buca","budino","buffone","buio","bulbo","buono","burlone","burrasca","bussola","busta","cadetto","caduco","calamaro","calcolo","calesse","calibro","calmo","caloria","cambusa","camerata","camicia","cammino","camola","campale","canapa","candela","cane","canino","canotto","cantina","capace","capello","capitolo","capogiro","cappero","capra","capsula","carapace","carcassa","cardo","carisma","carovana","carretto","cartolina","casaccio","cascata","caserma","caso","cassone","castello","casuale","catasta","catena","catrame","cauto","cavillo","cedibile","cedrata","cefalo","celebre","cellulare","cena","cenone","centesimo","ceramica","cercare","certo","cerume","cervello","cesoia","cespo","ceto","chela","chiaro","chicca","chiedere","chimera","china","chirurgo","chitarra","ciao","ciclismo","cifrare","cigno","cilindro","ciottolo","circa","cirrosi","citrico","cittadino","ciuffo","civetta","civile","classico","clinica","cloro","cocco","codardo","codice","coerente","cognome","collare","colmato","colore","colposo","coltivato","colza","coma","cometa","commando","comodo","computer","comune","conciso","condurre","conferma","congelare","coniuge","connesso","conoscere","consumo","continuo","convegno","coperto","copione","coppia","copricapo","corazza","cordata","coricato","cornice","corolla","corpo","corredo","corsia","cortese","cosmico","costante","cottura","covato","cratere","cravatta","creato","credere","cremoso","crescita","creta","criceto","crinale","crisi","critico","croce","cronaca","crostata","cruciale","crusca","cucire","cuculo","cugino","cullato","cupola","curatore","cursore","curvo","cuscino","custode","dado","daino","dalmata","damerino","daniela","dannoso","danzare","datato","davanti","davvero","debutto","decennio","deciso","declino","decollo","decreto","dedicato","definito","deforme","degno","delegare","delfino","delirio","delta","demenza","denotato","dentro","deposito","derapata","derivare","deroga","descritto","deserto","desiderio","desumere","detersivo","devoto","diametro","dicembre","diedro","difeso","diffuso","digerire","digitale","diluvio","dinamico","dinnanzi","dipinto","diploma","dipolo","diradare","dire","dirotto","dirupo","disagio","discreto","disfare","disgelo","disposto","distanza","disumano","dito","divano","divelto","dividere","divorato","doblone","docente","doganale","dogma","dolce","domato","domenica","dominare","dondolo","dono","dormire","dote","dottore","dovuto","dozzina","drago","druido","dubbio","dubitare","ducale","duna","duomo","duplice","duraturo","ebano","eccesso","ecco","eclissi","economia","edera","edicola","edile","editoria","educare","egemonia","egli","egoismo","egregio","elaborato","elargire","elegante","elencato","eletto","elevare","elfico","elica","elmo","elsa","eluso","emanato","emblema","emesso","emiro","emotivo","emozione","empirico","emulo","endemico","enduro","energia","enfasi","enoteca","entrare","enzima","epatite","epilogo","episodio","epocale","eppure","equatore","erario","erba","erboso","erede","eremita","erigere","ermetico","eroe","erosivo","errante","esagono","esame","esanime","esaudire","esca","esempio","esercito","esibito","esigente","esistere","esito","esofago","esortato","esoso","espanso","espresso","essenza","esso","esteso","estimare","estonia","estroso","esultare","etilico","etnico","etrusco","etto","euclideo","europa","evaso","evidenza","evitato","evoluto","evviva","fabbrica","faccenda","fachiro","falco","famiglia","fanale","fanfara","fango","fantasma","fare","farfalla","farinoso","farmaco","fascia","fastoso","fasullo","faticare","fato","favoloso","febbre","fecola","fede","fegato","felpa","feltro","femmina","fendere","fenomeno","fermento","ferro","fertile","fessura","festivo","fetta","feudo","fiaba","fiducia","fifa","figurato","filo","finanza","finestra","finire","fiore","fiscale","fisico","fiume","flacone","flamenco","flebo","flemma","florido","fluente","fluoro","fobico","focaccia","focoso","foderato","foglio","folata","folclore","folgore","fondente","fonetico","fonia","fontana","forbito","forchetta","foresta","formica","fornaio","foro","fortezza","forzare","fosfato","fosso","fracasso","frana","frassino","fratello","freccetta","frenata","fresco","frigo","frollino","fronde","frugale","frutta","fucilata","fucsia","fuggente","fulmine","fulvo","fumante","fumetto","fumoso","fune","funzione","fuoco","furbo","furgone","furore","fuso","futile","gabbiano","gaffe","galateo","gallina","galoppo","gambero","gamma","garanzia","garbo","garofano","garzone","gasdotto","gasolio","gastrico","gatto","gaudio","gazebo","gazzella","geco","gelatina","gelso","gemello","gemmato","gene","genitore","gennaio","genotipo","gergo","ghepardo","ghiaccio","ghisa","giallo","gilda","ginepro","giocare","gioiello","giorno","giove","girato","girone","gittata","giudizio","giurato","giusto","globulo","glutine","gnomo","gobba","golf","gomito","gommone","gonfio","gonna","governo","gracile","grado","grafico","grammo","grande","grattare","gravoso","grazia","greca","gregge","grifone","grigio","grinza","grotta","gruppo","guadagno","guaio","guanto","guardare","gufo","guidare","ibernato","icona","identico","idillio","idolo","idra","idrico","idrogeno","igiene","ignaro","ignorato","ilare","illeso","illogico","illudere","imballo","imbevuto","imbocco","imbuto","immane","immerso","immolato","impacco","impeto","impiego","importo","impronta","inalare","inarcare","inattivo","incanto","incendio","inchino","incisivo","incluso","incontro","incrocio","incubo","indagine","india","indole","inedito","infatti","infilare","inflitto","ingaggio","ingegno","inglese","ingordo","ingrosso","innesco","inodore","inoltrare","inondato","insano","insetto","insieme","insonnia","insulina","intasato","intero","intonaco","intuito","inumidire","invalido","invece","invito","iperbole","ipnotico","ipotesi","ippica","iride","irlanda","ironico","irrigato","irrorare","isolato","isotopo","isterico","istituto","istrice","italia","iterare","labbro","labirinto","lacca","lacerato","lacrima","lacuna","laddove","lago","lampo","lancetta","lanterna","lardoso","larga","laringe","lastra","latenza","latino","lattuga","lavagna","lavoro","legale","leggero","lembo","lentezza","lenza","leone","lepre","lesivo","lessato","lesto","letterale","leva","levigato","libero","lido","lievito","lilla","limatura","limitare","limpido","lineare","lingua","liquido","lira","lirica","lisca","lite","litigio","livrea","locanda","lode","logica","lombare","londra","longevo","loquace","lorenzo","loto","lotteria","luce","lucidato","lumaca","luminoso","lungo","lupo","luppolo","lusinga","lusso","lutto","macabro","macchina","macero","macinato","madama","magico","maglia","magnete","magro","maiolica","malafede","malgrado","malinteso","malsano","malto","malumore","mana","mancia","mandorla","mangiare","manifesto","mannaro","manovra","mansarda","mantide","manubrio","mappa","maratona","marcire","maretta","marmo","marsupio","maschera","massaia","mastino","materasso","matricola","mattone","maturo","mazurca","meandro","meccanico","mecenate","medesimo","meditare","mega","melassa","melis","melodia","meninge","meno","mensola","mercurio","merenda","merlo","meschino","mese","messere","mestolo","metallo","metodo","mettere","miagolare","mica","micelio","michele","microbo","midollo","miele","migliore","milano","milite","mimosa","minerale","mini","minore","mirino","mirtillo","miscela","missiva","misto","misurare","mitezza","mitigare","mitra","mittente","mnemonico","modello","modifica","modulo","mogano","mogio","mole","molosso","monastero","monco","mondina","monetario","monile","monotono","monsone","montato","monviso","mora","mordere","morsicato","mostro","motivato","motosega","motto","movenza","movimento","mozzo","mucca","mucosa","muffa","mughetto","mugnaio","mulatto","mulinello","multiplo","mummia","munto","muovere","murale","musa","muscolo","musica","mutevole","muto","nababbo","nafta","nanometro","narciso","narice","narrato","nascere","nastrare","naturale","nautica","naviglio","nebulosa","necrosi","negativo","negozio","nemmeno","neofita","neretto","nervo","nessuno","nettuno","neutrale","neve","nevrotico","nicchia","ninfa","nitido","nobile","nocivo","nodo","nome","nomina","nordico","normale","norvegese","nostrano","notare","notizia","notturno","novella","nucleo","nulla","numero","nuovo","nutrire","nuvola","nuziale","oasi","obbedire","obbligo","obelisco","oblio","obolo","obsoleto","occasione","occhio","occidente","occorrere","occultare","ocra","oculato","odierno","odorare","offerta","offrire","offuscato","oggetto","oggi","ognuno","olandese","olfatto","oliato","oliva","ologramma","oltre","omaggio","ombelico","ombra","omega","omissione","ondoso","onere","onice","onnivoro","onorevole","onta","operato","opinione","opposto","oracolo","orafo","ordine","orecchino","orefice","orfano","organico","origine","orizzonte","orma","ormeggio","ornativo","orologio","orrendo","orribile","ortensia","ortica","orzata","orzo","osare","oscurare","osmosi","ospedale","ospite","ossa","ossidare","ostacolo","oste","otite","otre","ottagono","ottimo","ottobre","ovale","ovest","ovino","oviparo","ovocito","ovunque","ovviare","ozio","pacchetto","pace","pacifico","padella","padrone","paese","paga","pagina","palazzina","palesare","pallido","palo","palude","pandoro","pannello","paolo","paonazzo","paprica","parabola","parcella","parere","pargolo","pari","parlato","parola","partire","parvenza","parziale","passivo","pasticca","patacca","patologia","pattume","pavone","peccato","pedalare","pedonale","peggio","peloso","penare","pendice","penisola","pennuto","penombra","pensare","pentola","pepe","pepita","perbene","percorso","perdonato","perforare","pergamena","periodo","permesso","perno","perplesso","persuaso","pertugio","pervaso","pesatore","pesista","peso","pestifero","petalo","pettine","petulante","pezzo","piacere","pianta","piattino","piccino","picozza","piega","pietra","piffero","pigiama","pigolio","pigro","pila","pilifero","pillola","pilota","pimpante","pineta","pinna","pinolo","pioggia","piombo","piramide","piretico","pirite","pirolisi","pitone","pizzico","placebo","planare","plasma","platano","plenario","pochezza","poderoso","podismo","poesia","poggiare","polenta","poligono","pollice","polmonite","polpetta","polso","poltrona","polvere","pomice","pomodoro","ponte","popoloso","porfido","poroso","porpora","porre","portata","posa","positivo","possesso","postulato","potassio","potere","pranzo","prassi","pratica","precluso","predica","prefisso","pregiato","prelievo","premere","prenotare","preparato","presenza","pretesto","prevalso","prima","principe","privato","problema","procura","produrre","profumo","progetto","prolunga","promessa","pronome","proposta","proroga","proteso","prova","prudente","prugna","prurito","psiche","pubblico","pudica","pugilato","pugno","pulce","pulito","pulsante","puntare","pupazzo","pupilla","puro","quadro","qualcosa","quasi","querela","quota","raccolto","raddoppio","radicale","radunato","raffica","ragazzo","ragione","ragno","ramarro","ramingo","ramo","randagio","rantolare","rapato","rapina","rappreso","rasatura","raschiato","rasente","rassegna","rastrello","rata","ravveduto","reale","recepire","recinto","recluta","recondito","recupero","reddito","redimere","regalato","registro","regola","regresso","relazione","remare","remoto","renna","replica","reprimere","reputare","resa","residente","responso","restauro","rete","retina","retorica","rettifica","revocato","riassunto","ribadire","ribelle","ribrezzo","ricarica","ricco","ricevere","riciclato","ricordo","ricreduto","ridicolo","ridurre","rifasare","riflesso","riforma","rifugio","rigare","rigettato","righello","rilassato","rilevato","rimanere","rimbalzo","rimedio","rimorchio","rinascita","rincaro","rinforzo","rinnovo","rinomato","rinsavito","rintocco","rinuncia","rinvenire","riparato","ripetuto","ripieno","riportare","ripresa","ripulire","risata","rischio","riserva","risibile","riso","rispetto","ristoro","risultato","risvolto","ritardo","ritegno","ritmico","ritrovo","riunione","riva","riverso","rivincita","rivolto","rizoma","roba","robotico","robusto","roccia","roco","rodaggio","rodere","roditore","rogito","rollio","romantico","rompere","ronzio","rosolare","rospo","rotante","rotondo","rotula","rovescio","rubizzo","rubrica","ruga","rullino","rumine","rumoroso","ruolo","rupe","russare","rustico","sabato","sabbiare","sabotato","sagoma","salasso","saldatura","salgemma","salivare","salmone","salone","saltare","saluto","salvo","sapere","sapido","saporito","saraceno","sarcasmo","sarto","sassoso","satellite","satira","satollo","saturno","savana","savio","saziato","sbadiglio","sbalzo","sbancato","sbarra","sbattere","sbavare","sbendare","sbirciare","sbloccato","sbocciato","sbrinare","sbruffone","sbuffare","scabroso","scadenza","scala","scambiare","scandalo","scapola","scarso","scatenare","scavato","scelto","scenico","scettro","scheda","schiena","sciarpa","scienza","scindere","scippo","sciroppo","scivolo","sclerare","scodella","scolpito","scomparto","sconforto","scoprire","scorta","scossone","scozzese","scriba","scrollare","scrutinio","scuderia","scultore","scuola","scuro","scusare","sdebitare","sdoganare","seccatura","secondo","sedano","seggiola","segnalato","segregato","seguito","selciato","selettivo","sella","selvaggio","semaforo","sembrare","seme","seminato","sempre","senso","sentire","sepolto","sequenza","serata","serbato","sereno","serio","serpente","serraglio","servire","sestina","setola","settimana","sfacelo","sfaldare","sfamato","sfarzoso","sfaticato","sfera","sfida","sfilato","sfinge","sfocato","sfoderare","sfogo","sfoltire","sforzato","sfratto","sfruttato","sfuggito","sfumare","sfuso","sgabello","sgarbato","sgonfiare","sgorbio","sgrassato","sguardo","sibilo","siccome","sierra","sigla","signore","silenzio","sillaba","simbolo","simpatico","simulato","sinfonia","singolo","sinistro","sino","sintesi","sinusoide","sipario","sisma","sistole","situato","slitta","slogatura","sloveno","smarrito","smemorato","smentito","smeraldo","smilzo","smontare","smottato","smussato","snellire","snervato","snodo","sobbalzo","sobrio","soccorso","sociale","sodale","soffitto","sogno","soldato","solenne","solido","sollazzo","solo","solubile","solvente","somatico","somma","sonda","sonetto","sonnifero","sopire","soppeso","sopra","sorgere","sorpasso","sorriso","sorso","sorteggio","sorvolato","sospiro","sosta","sottile","spada","spalla","spargere","spatola","spavento","spazzola","specie","spedire","spegnere","spelatura","speranza","spessore","spettrale","spezzato","spia","spigoloso","spillato","spinoso","spirale","splendido","sportivo","sposo","spranga","sprecare","spronato","spruzzo","spuntino","squillo","sradicare","srotolato","stabile","stacco","staffa","stagnare","stampato","stantio","starnuto","stasera","statuto","stelo","steppa","sterzo","stiletto","stima","stirpe","stivale","stizzoso","stonato","storico","strappo","stregato","stridulo","strozzare","strutto","stuccare","stufo","stupendo","subentro","succoso","sudore","suggerito","sugo","sultano","suonare","superbo","supporto","surgelato","surrogato","sussurro","sutura","svagare","svedese","sveglio","svelare","svenuto","svezia","sviluppo","svista","svizzera","svolta","svuotare","tabacco","tabulato","tacciare","taciturno","tale","talismano","tampone","tannino","tara","tardivo","targato","tariffa","tarpare","tartaruga","tasto","tattico","taverna","tavolata","tazza","teca","tecnico","telefono","temerario","tempo","temuto","tendone","tenero","tensione","tentacolo","teorema","terme","terrazzo","terzetto","tesi","tesserato","testato","tetro","tettoia","tifare","tigella","timbro","tinto","tipico","tipografo","tiraggio","tiro","titanio","titolo","titubante","tizio","tizzone","toccare","tollerare","tolto","tombola","tomo","tonfo","tonsilla","topazio","topologia","toppa","torba","tornare","torrone","tortora","toscano","tossire","tostatura","totano","trabocco","trachea","trafila","tragedia","tralcio","tramonto","transito","trapano","trarre","trasloco","trattato","trave","treccia","tremolio","trespolo","tributo","tricheco","trifoglio","trillo","trincea","trio","tristezza","triturato","trivella","tromba","trono","troppo","trottola","trovare","truccato","tubatura","tuffato","tulipano","tumulto","tunisia","turbare","turchino","tuta","tutela","ubicato","uccello","uccisore","udire","uditivo","uffa","ufficio","uguale","ulisse","ultimato","umano","umile","umorismo","uncinetto","ungere","ungherese","unicorno","unificato","unisono","unitario","unte","uovo","upupa","uragano","urgenza","urlo","usanza","usato","uscito","usignolo","usuraio","utensile","utilizzo","utopia","vacante","vaccinato","vagabondo","vagliato","valanga","valgo","valico","valletta","valoroso","valutare","valvola","vampata","vangare","vanitoso","vano","vantaggio","vanvera","vapore","varano","varcato","variante","vasca","vedetta","vedova","veduto","vegetale","veicolo","velcro","velina","velluto","veloce","venato","vendemmia","vento","verace","verbale","vergogna","verifica","vero","verruca","verticale","vescica","vessillo","vestale","veterano","vetrina","vetusto","viandante","vibrante","vicenda","vichingo","vicinanza","vidimare","vigilia","vigneto","vigore","vile","villano","vimini","vincitore","viola","vipera","virgola","virologo","virulento","viscoso","visione","vispo","vissuto","visura","vita","vitello","vittima","vivanda","vivido","viziare","voce","voga","volatile","volere","volpe","voragine","vulcano","zampogna","zanna","zappato","zattera","zavorra","zefiro","zelante","zelo","zenzero","zerbino","zibetto","zinco","zircone","zitto","zolla","zotico","zucchero","zufolo","zulu","zuppa"]'), Jl = /* @__PURE__ */ JSON.parse('["ábaco","abdomen","abeja","abierto","abogado","abono","aborto","abrazo","abrir","abuelo","abuso","acabar","academia","acceso","acción","aceite","acelga","acento","aceptar","ácido","aclarar","acné","acoger","acoso","activo","acto","actriz","actuar","acudir","acuerdo","acusar","adicto","admitir","adoptar","adorno","aduana","adulto","aéreo","afectar","afición","afinar","afirmar","ágil","agitar","agonía","agosto","agotar","agregar","agrio","agua","agudo","águila","aguja","ahogo","ahorro","aire","aislar","ajedrez","ajeno","ajuste","alacrán","alambre","alarma","alba","álbum","alcalde","aldea","alegre","alejar","alerta","aleta","alfiler","alga","algodón","aliado","aliento","alivio","alma","almeja","almíbar","altar","alteza","altivo","alto","altura","alumno","alzar","amable","amante","amapola","amargo","amasar","ámbar","ámbito","ameno","amigo","amistad","amor","amparo","amplio","ancho","anciano","ancla","andar","andén","anemia","ángulo","anillo","ánimo","anís","anotar","antena","antiguo","antojo","anual","anular","anuncio","añadir","añejo","año","apagar","aparato","apetito","apio","aplicar","apodo","aporte","apoyo","aprender","aprobar","apuesta","apuro","arado","araña","arar","árbitro","árbol","arbusto","archivo","arco","arder","ardilla","arduo","área","árido","aries","armonía","arnés","aroma","arpa","arpón","arreglo","arroz","arruga","arte","artista","asa","asado","asalto","ascenso","asegurar","aseo","asesor","asiento","asilo","asistir","asno","asombro","áspero","astilla","astro","astuto","asumir","asunto","atajo","ataque","atar","atento","ateo","ático","atleta","átomo","atraer","atroz","atún","audaz","audio","auge","aula","aumento","ausente","autor","aval","avance","avaro","ave","avellana","avena","avestruz","avión","aviso","ayer","ayuda","ayuno","azafrán","azar","azote","azúcar","azufre","azul","baba","babor","bache","bahía","baile","bajar","balanza","balcón","balde","bambú","banco","banda","baño","barba","barco","barniz","barro","báscula","bastón","basura","batalla","batería","batir","batuta","baúl","bazar","bebé","bebida","bello","besar","beso","bestia","bicho","bien","bingo","blanco","bloque","blusa","boa","bobina","bobo","boca","bocina","boda","bodega","boina","bola","bolero","bolsa","bomba","bondad","bonito","bono","bonsái","borde","borrar","bosque","bote","botín","bóveda","bozal","bravo","brazo","brecha","breve","brillo","brinco","brisa","broca","broma","bronce","brote","bruja","brusco","bruto","buceo","bucle","bueno","buey","bufanda","bufón","búho","buitre","bulto","burbuja","burla","burro","buscar","butaca","buzón","caballo","cabeza","cabina","cabra","cacao","cadáver","cadena","caer","café","caída","caimán","caja","cajón","cal","calamar","calcio","caldo","calidad","calle","calma","calor","calvo","cama","cambio","camello","camino","campo","cáncer","candil","canela","canguro","canica","canto","caña","cañón","caoba","caos","capaz","capitán","capote","captar","capucha","cara","carbón","cárcel","careta","carga","cariño","carne","carpeta","carro","carta","casa","casco","casero","caspa","castor","catorce","catre","caudal","causa","cazo","cebolla","ceder","cedro","celda","célebre","celoso","célula","cemento","ceniza","centro","cerca","cerdo","cereza","cero","cerrar","certeza","césped","cetro","chacal","chaleco","champú","chancla","chapa","charla","chico","chiste","chivo","choque","choza","chuleta","chupar","ciclón","ciego","cielo","cien","cierto","cifra","cigarro","cima","cinco","cine","cinta","ciprés","circo","ciruela","cisne","cita","ciudad","clamor","clan","claro","clase","clave","cliente","clima","clínica","cobre","cocción","cochino","cocina","coco","código","codo","cofre","coger","cohete","cojín","cojo","cola","colcha","colegio","colgar","colina","collar","colmo","columna","combate","comer","comida","cómodo","compra","conde","conejo","conga","conocer","consejo","contar","copa","copia","corazón","corbata","corcho","cordón","corona","correr","coser","cosmos","costa","cráneo","cráter","crear","crecer","creído","crema","cría","crimen","cripta","crisis","cromo","crónica","croqueta","crudo","cruz","cuadro","cuarto","cuatro","cubo","cubrir","cuchara","cuello","cuento","cuerda","cuesta","cueva","cuidar","culebra","culpa","culto","cumbre","cumplir","cuna","cuneta","cuota","cupón","cúpula","curar","curioso","curso","curva","cutis","dama","danza","dar","dardo","dátil","deber","débil","década","decir","dedo","defensa","definir","dejar","delfín","delgado","delito","demora","denso","dental","deporte","derecho","derrota","desayuno","deseo","desfile","desnudo","destino","desvío","detalle","detener","deuda","día","diablo","diadema","diamante","diana","diario","dibujo","dictar","diente","dieta","diez","difícil","digno","dilema","diluir","dinero","directo","dirigir","disco","diseño","disfraz","diva","divino","doble","doce","dolor","domingo","don","donar","dorado","dormir","dorso","dos","dosis","dragón","droga","ducha","duda","duelo","dueño","dulce","dúo","duque","durar","dureza","duro","ébano","ebrio","echar","eco","ecuador","edad","edición","edificio","editor","educar","efecto","eficaz","eje","ejemplo","elefante","elegir","elemento","elevar","elipse","élite","elixir","elogio","eludir","embudo","emitir","emoción","empate","empeño","empleo","empresa","enano","encargo","enchufe","encía","enemigo","enero","enfado","enfermo","engaño","enigma","enlace","enorme","enredo","ensayo","enseñar","entero","entrar","envase","envío","época","equipo","erizo","escala","escena","escolar","escribir","escudo","esencia","esfera","esfuerzo","espada","espejo","espía","esposa","espuma","esquí","estar","este","estilo","estufa","etapa","eterno","ética","etnia","evadir","evaluar","evento","evitar","exacto","examen","exceso","excusa","exento","exigir","exilio","existir","éxito","experto","explicar","exponer","extremo","fábrica","fábula","fachada","fácil","factor","faena","faja","falda","fallo","falso","faltar","fama","familia","famoso","faraón","farmacia","farol","farsa","fase","fatiga","fauna","favor","fax","febrero","fecha","feliz","feo","feria","feroz","fértil","fervor","festín","fiable","fianza","fiar","fibra","ficción","ficha","fideo","fiebre","fiel","fiera","fiesta","figura","fijar","fijo","fila","filete","filial","filtro","fin","finca","fingir","finito","firma","flaco","flauta","flecha","flor","flota","fluir","flujo","flúor","fobia","foca","fogata","fogón","folio","folleto","fondo","forma","forro","fortuna","forzar","fosa","foto","fracaso","frágil","franja","frase","fraude","freír","freno","fresa","frío","frito","fruta","fuego","fuente","fuerza","fuga","fumar","función","funda","furgón","furia","fusil","fútbol","futuro","gacela","gafas","gaita","gajo","gala","galería","gallo","gamba","ganar","gancho","ganga","ganso","garaje","garza","gasolina","gastar","gato","gavilán","gemelo","gemir","gen","género","genio","gente","geranio","gerente","germen","gesto","gigante","gimnasio","girar","giro","glaciar","globo","gloria","gol","golfo","goloso","golpe","goma","gordo","gorila","gorra","gota","goteo","gozar","grada","gráfico","grano","grasa","gratis","grave","grieta","grillo","gripe","gris","grito","grosor","grúa","grueso","grumo","grupo","guante","guapo","guardia","guerra","guía","guiño","guion","guiso","guitarra","gusano","gustar","haber","hábil","hablar","hacer","hacha","hada","hallar","hamaca","harina","haz","hazaña","hebilla","hebra","hecho","helado","helio","hembra","herir","hermano","héroe","hervir","hielo","hierro","hígado","higiene","hijo","himno","historia","hocico","hogar","hoguera","hoja","hombre","hongo","honor","honra","hora","hormiga","horno","hostil","hoyo","hueco","huelga","huerta","hueso","huevo","huida","huir","humano","húmedo","humilde","humo","hundir","huracán","hurto","icono","ideal","idioma","ídolo","iglesia","iglú","igual","ilegal","ilusión","imagen","imán","imitar","impar","imperio","imponer","impulso","incapaz","índice","inerte","infiel","informe","ingenio","inicio","inmenso","inmune","innato","insecto","instante","interés","íntimo","intuir","inútil","invierno","ira","iris","ironía","isla","islote","jabalí","jabón","jamón","jarabe","jardín","jarra","jaula","jazmín","jefe","jeringa","jinete","jornada","joroba","joven","joya","juerga","jueves","juez","jugador","jugo","juguete","juicio","junco","jungla","junio","juntar","júpiter","jurar","justo","juvenil","juzgar","kilo","koala","labio","lacio","lacra","lado","ladrón","lagarto","lágrima","laguna","laico","lamer","lámina","lámpara","lana","lancha","langosta","lanza","lápiz","largo","larva","lástima","lata","látex","latir","laurel","lavar","lazo","leal","lección","leche","lector","leer","legión","legumbre","lejano","lengua","lento","leña","león","leopardo","lesión","letal","letra","leve","leyenda","libertad","libro","licor","líder","lidiar","lienzo","liga","ligero","lima","límite","limón","limpio","lince","lindo","línea","lingote","lino","linterna","líquido","liso","lista","litera","litio","litro","llaga","llama","llanto","llave","llegar","llenar","llevar","llorar","llover","lluvia","lobo","loción","loco","locura","lógica","logro","lombriz","lomo","lonja","lote","lucha","lucir","lugar","lujo","luna","lunes","lupa","lustro","luto","luz","maceta","macho","madera","madre","maduro","maestro","mafia","magia","mago","maíz","maldad","maleta","malla","malo","mamá","mambo","mamut","manco","mando","manejar","manga","maniquí","manjar","mano","manso","manta","mañana","mapa","máquina","mar","marco","marea","marfil","margen","marido","mármol","marrón","martes","marzo","masa","máscara","masivo","matar","materia","matiz","matriz","máximo","mayor","mazorca","mecha","medalla","medio","médula","mejilla","mejor","melena","melón","memoria","menor","mensaje","mente","menú","mercado","merengue","mérito","mes","mesón","meta","meter","método","metro","mezcla","miedo","miel","miembro","miga","mil","milagro","militar","millón","mimo","mina","minero","mínimo","minuto","miope","mirar","misa","miseria","misil","mismo","mitad","mito","mochila","moción","moda","modelo","moho","mojar","molde","moler","molino","momento","momia","monarca","moneda","monja","monto","moño","morada","morder","moreno","morir","morro","morsa","mortal","mosca","mostrar","motivo","mover","móvil","mozo","mucho","mudar","mueble","muela","muerte","muestra","mugre","mujer","mula","muleta","multa","mundo","muñeca","mural","muro","músculo","museo","musgo","música","muslo","nácar","nación","nadar","naipe","naranja","nariz","narrar","nasal","natal","nativo","natural","náusea","naval","nave","navidad","necio","néctar","negar","negocio","negro","neón","nervio","neto","neutro","nevar","nevera","nicho","nido","niebla","nieto","niñez","niño","nítido","nivel","nobleza","noche","nómina","noria","norma","norte","nota","noticia","novato","novela","novio","nube","nuca","núcleo","nudillo","nudo","nuera","nueve","nuez","nulo","número","nutria","oasis","obeso","obispo","objeto","obra","obrero","observar","obtener","obvio","oca","ocaso","océano","ochenta","ocho","ocio","ocre","octavo","octubre","oculto","ocupar","ocurrir","odiar","odio","odisea","oeste","ofensa","oferta","oficio","ofrecer","ogro","oído","oír","ojo","ola","oleada","olfato","olivo","olla","olmo","olor","olvido","ombligo","onda","onza","opaco","opción","ópera","opinar","oponer","optar","óptica","opuesto","oración","orador","oral","órbita","orca","orden","oreja","órgano","orgía","orgullo","oriente","origen","orilla","oro","orquesta","oruga","osadía","oscuro","osezno","oso","ostra","otoño","otro","oveja","óvulo","óxido","oxígeno","oyente","ozono","pacto","padre","paella","página","pago","país","pájaro","palabra","palco","paleta","pálido","palma","paloma","palpar","pan","panal","pánico","pantera","pañuelo","papá","papel","papilla","paquete","parar","parcela","pared","parir","paro","párpado","parque","párrafo","parte","pasar","paseo","pasión","paso","pasta","pata","patio","patria","pausa","pauta","pavo","payaso","peatón","pecado","pecera","pecho","pedal","pedir","pegar","peine","pelar","peldaño","pelea","peligro","pellejo","pelo","peluca","pena","pensar","peñón","peón","peor","pepino","pequeño","pera","percha","perder","pereza","perfil","perico","perla","permiso","perro","persona","pesa","pesca","pésimo","pestaña","pétalo","petróleo","pez","pezuña","picar","pichón","pie","piedra","pierna","pieza","pijama","pilar","piloto","pimienta","pino","pintor","pinza","piña","piojo","pipa","pirata","pisar","piscina","piso","pista","pitón","pizca","placa","plan","plata","playa","plaza","pleito","pleno","plomo","pluma","plural","pobre","poco","poder","podio","poema","poesía","poeta","polen","policía","pollo","polvo","pomada","pomelo","pomo","pompa","poner","porción","portal","posada","poseer","posible","poste","potencia","potro","pozo","prado","precoz","pregunta","premio","prensa","preso","previo","primo","príncipe","prisión","privar","proa","probar","proceso","producto","proeza","profesor","programa","prole","promesa","pronto","propio","próximo","prueba","público","puchero","pudor","pueblo","puerta","puesto","pulga","pulir","pulmón","pulpo","pulso","puma","punto","puñal","puño","pupa","pupila","puré","quedar","queja","quemar","querer","queso","quieto","química","quince","quitar","rábano","rabia","rabo","ración","radical","raíz","rama","rampa","rancho","rango","rapaz","rápido","rapto","rasgo","raspa","rato","rayo","raza","razón","reacción","realidad","rebaño","rebote","recaer","receta","rechazo","recoger","recreo","recto","recurso","red","redondo","reducir","reflejo","reforma","refrán","refugio","regalo","regir","regla","regreso","rehén","reino","reír","reja","relato","relevo","relieve","relleno","reloj","remar","remedio","remo","rencor","rendir","renta","reparto","repetir","reposo","reptil","res","rescate","resina","respeto","resto","resumen","retiro","retorno","retrato","reunir","revés","revista","rey","rezar","rico","riego","rienda","riesgo","rifa","rígido","rigor","rincón","riñón","río","riqueza","risa","ritmo","rito","rizo","roble","roce","rociar","rodar","rodeo","rodilla","roer","rojizo","rojo","romero","romper","ron","ronco","ronda","ropa","ropero","rosa","rosca","rostro","rotar","rubí","rubor","rudo","rueda","rugir","ruido","ruina","ruleta","rulo","rumbo","rumor","ruptura","ruta","rutina","sábado","saber","sabio","sable","sacar","sagaz","sagrado","sala","saldo","salero","salir","salmón","salón","salsa","salto","salud","salvar","samba","sanción","sandía","sanear","sangre","sanidad","sano","santo","sapo","saque","sardina","sartén","sastre","satán","sauna","saxofón","sección","seco","secreto","secta","sed","seguir","seis","sello","selva","semana","semilla","senda","sensor","señal","señor","separar","sepia","sequía","ser","serie","sermón","servir","sesenta","sesión","seta","setenta","severo","sexo","sexto","sidra","siesta","siete","siglo","signo","sílaba","silbar","silencio","silla","símbolo","simio","sirena","sistema","sitio","situar","sobre","socio","sodio","sol","solapa","soldado","soledad","sólido","soltar","solución","sombra","sondeo","sonido","sonoro","sonrisa","sopa","soplar","soporte","sordo","sorpresa","sorteo","sostén","sótano","suave","subir","suceso","sudor","suegra","suelo","sueño","suerte","sufrir","sujeto","sultán","sumar","superar","suplir","suponer","supremo","sur","surco","sureño","surgir","susto","sutil","tabaco","tabique","tabla","tabú","taco","tacto","tajo","talar","talco","talento","talla","talón","tamaño","tambor","tango","tanque","tapa","tapete","tapia","tapón","taquilla","tarde","tarea","tarifa","tarjeta","tarot","tarro","tarta","tatuaje","tauro","taza","tazón","teatro","techo","tecla","técnica","tejado","tejer","tejido","tela","teléfono","tema","temor","templo","tenaz","tender","tener","tenis","tenso","teoría","terapia","terco","término","ternura","terror","tesis","tesoro","testigo","tetera","texto","tez","tibio","tiburón","tiempo","tienda","tierra","tieso","tigre","tijera","tilde","timbre","tímido","timo","tinta","tío","típico","tipo","tira","tirón","titán","títere","título","tiza","toalla","tobillo","tocar","tocino","todo","toga","toldo","tomar","tono","tonto","topar","tope","toque","tórax","torero","tormenta","torneo","toro","torpedo","torre","torso","tortuga","tos","tosco","toser","tóxico","trabajo","tractor","traer","tráfico","trago","traje","tramo","trance","trato","trauma","trazar","trébol","tregua","treinta","tren","trepar","tres","tribu","trigo","tripa","triste","triunfo","trofeo","trompa","tronco","tropa","trote","trozo","truco","trueno","trufa","tubería","tubo","tuerto","tumba","tumor","túnel","túnica","turbina","turismo","turno","tutor","ubicar","úlcera","umbral","unidad","unir","universo","uno","untar","uña","urbano","urbe","urgente","urna","usar","usuario","útil","utopía","uva","vaca","vacío","vacuna","vagar","vago","vaina","vajilla","vale","válido","valle","valor","válvula","vampiro","vara","variar","varón","vaso","vecino","vector","vehículo","veinte","vejez","vela","velero","veloz","vena","vencer","venda","veneno","vengar","venir","venta","venus","ver","verano","verbo","verde","vereda","verja","verso","verter","vía","viaje","vibrar","vicio","víctima","vida","vídeo","vidrio","viejo","viernes","vigor","vil","villa","vinagre","vino","viñedo","violín","viral","virgo","virtud","visor","víspera","vista","vitamina","viudo","vivaz","vivero","vivir","vivo","volcán","volumen","volver","voraz","votar","voto","voz","vuelo","vulgar","yacer","yate","yegua","yema","yerno","yeso","yodo","yoga","yogur","zafiro","zanja","zapato","zarza","zona","zorro","zumo","zurdo"]'), Yl = /* @__PURE__ */ JSON.parse('["あいこくしん","あいさつ","あいだ","あおぞら","あかちゃん","あきる","あけがた","あける","あこがれる","あさい","あさひ","あしあと","あじわう","あずかる","あずき","あそぶ","あたえる","あたためる","あたりまえ","あたる","あつい","あつかう","あっしゅく","あつまり","あつめる","あてな","あてはまる","あひる","あぶら","あぶる","あふれる","あまい","あまど","あまやかす","あまり","あみもの","あめりか","あやまる","あゆむ","あらいぐま","あらし","あらすじ","あらためる","あらゆる","あらわす","ありがとう","あわせる","あわてる","あんい","あんがい","あんこ","あんぜん","あんてい","あんない","あんまり","いいだす","いおん","いがい","いがく","いきおい","いきなり","いきもの","いきる","いくじ","いくぶん","いけばな","いけん","いこう","いこく","いこつ","いさましい","いさん","いしき","いじゅう","いじょう","いじわる","いずみ","いずれ","いせい","いせえび","いせかい","いせき","いぜん","いそうろう","いそがしい","いだい","いだく","いたずら","いたみ","いたりあ","いちおう","いちじ","いちど","いちば","いちぶ","いちりゅう","いつか","いっしゅん","いっせい","いっそう","いったん","いっち","いってい","いっぽう","いてざ","いてん","いどう","いとこ","いない","いなか","いねむり","いのち","いのる","いはつ","いばる","いはん","いびき","いひん","いふく","いへん","いほう","いみん","いもうと","いもたれ","いもり","いやがる","いやす","いよかん","いよく","いらい","いらすと","いりぐち","いりょう","いれい","いれもの","いれる","いろえんぴつ","いわい","いわう","いわかん","いわば","いわゆる","いんげんまめ","いんさつ","いんしょう","いんよう","うえき","うえる","うおざ","うがい","うかぶ","うかべる","うきわ","うくらいな","うくれれ","うけたまわる","うけつけ","うけとる","うけもつ","うける","うごかす","うごく","うこん","うさぎ","うしなう","うしろがみ","うすい","うすぎ","うすぐらい","うすめる","うせつ","うちあわせ","うちがわ","うちき","うちゅう","うっかり","うつくしい","うったえる","うつる","うどん","うなぎ","うなじ","うなずく","うなる","うねる","うのう","うぶげ","うぶごえ","うまれる","うめる","うもう","うやまう","うよく","うらがえす","うらぐち","うらない","うりあげ","うりきれ","うるさい","うれしい","うれゆき","うれる","うろこ","うわき","うわさ","うんこう","うんちん","うんてん","うんどう","えいえん","えいが","えいきょう","えいご","えいせい","えいぶん","えいよう","えいわ","えおり","えがお","えがく","えきたい","えくせる","えしゃく","えすて","えつらん","えのぐ","えほうまき","えほん","えまき","えもじ","えもの","えらい","えらぶ","えりあ","えんえん","えんかい","えんぎ","えんげき","えんしゅう","えんぜつ","えんそく","えんちょう","えんとつ","おいかける","おいこす","おいしい","おいつく","おうえん","おうさま","おうじ","おうせつ","おうたい","おうふく","おうべい","おうよう","おえる","おおい","おおう","おおどおり","おおや","おおよそ","おかえり","おかず","おがむ","おかわり","おぎなう","おきる","おくさま","おくじょう","おくりがな","おくる","おくれる","おこす","おこなう","おこる","おさえる","おさない","おさめる","おしいれ","おしえる","おじぎ","おじさん","おしゃれ","おそらく","おそわる","おたがい","おたく","おだやか","おちつく","おっと","おつり","おでかけ","おとしもの","おとなしい","おどり","おどろかす","おばさん","おまいり","おめでとう","おもいで","おもう","おもたい","おもちゃ","おやつ","おやゆび","およぼす","おらんだ","おろす","おんがく","おんけい","おんしゃ","おんせん","おんだん","おんちゅう","おんどけい","かあつ","かいが","がいき","がいけん","がいこう","かいさつ","かいしゃ","かいすいよく","かいぜん","かいぞうど","かいつう","かいてん","かいとう","かいふく","がいへき","かいほう","かいよう","がいらい","かいわ","かえる","かおり","かかえる","かがく","かがし","かがみ","かくご","かくとく","かざる","がぞう","かたい","かたち","がちょう","がっきゅう","がっこう","がっさん","がっしょう","かなざわし","かのう","がはく","かぶか","かほう","かほご","かまう","かまぼこ","かめれおん","かゆい","かようび","からい","かるい","かろう","かわく","かわら","がんか","かんけい","かんこう","かんしゃ","かんそう","かんたん","かんち","がんばる","きあい","きあつ","きいろ","ぎいん","きうい","きうん","きえる","きおう","きおく","きおち","きおん","きかい","きかく","きかんしゃ","ききて","きくばり","きくらげ","きけんせい","きこう","きこえる","きこく","きさい","きさく","きさま","きさらぎ","ぎじかがく","ぎしき","ぎじたいけん","ぎじにってい","ぎじゅつしゃ","きすう","きせい","きせき","きせつ","きそう","きぞく","きぞん","きたえる","きちょう","きつえん","ぎっちり","きつつき","きつね","きてい","きどう","きどく","きない","きなが","きなこ","きぬごし","きねん","きのう","きのした","きはく","きびしい","きひん","きふく","きぶん","きぼう","きほん","きまる","きみつ","きむずかしい","きめる","きもだめし","きもち","きもの","きゃく","きやく","ぎゅうにく","きよう","きょうりゅう","きらい","きらく","きりん","きれい","きれつ","きろく","ぎろん","きわめる","ぎんいろ","きんかくじ","きんじょ","きんようび","ぐあい","くいず","くうかん","くうき","くうぐん","くうこう","ぐうせい","くうそう","ぐうたら","くうふく","くうぼ","くかん","くきょう","くげん","ぐこう","くさい","くさき","くさばな","くさる","くしゃみ","くしょう","くすのき","くすりゆび","くせげ","くせん","ぐたいてき","くださる","くたびれる","くちこみ","くちさき","くつした","ぐっすり","くつろぐ","くとうてん","くどく","くなん","くねくね","くのう","くふう","くみあわせ","くみたてる","くめる","くやくしょ","くらす","くらべる","くるま","くれる","くろう","くわしい","ぐんかん","ぐんしょく","ぐんたい","ぐんて","けあな","けいかく","けいけん","けいこ","けいさつ","げいじゅつ","けいたい","げいのうじん","けいれき","けいろ","けおとす","けおりもの","げきか","げきげん","げきだん","げきちん","げきとつ","げきは","げきやく","げこう","げこくじょう","げざい","けさき","げざん","けしき","けしごむ","けしょう","げすと","けたば","けちゃっぷ","けちらす","けつあつ","けつい","けつえき","けっこん","けつじょ","けっせき","けってい","けつまつ","げつようび","げつれい","けつろん","げどく","けとばす","けとる","けなげ","けなす","けなみ","けぬき","げねつ","けねん","けはい","げひん","けぶかい","げぼく","けまり","けみかる","けむし","けむり","けもの","けらい","けろけろ","けわしい","けんい","けんえつ","けんお","けんか","げんき","けんげん","けんこう","けんさく","けんしゅう","けんすう","げんそう","けんちく","けんてい","けんとう","けんない","けんにん","げんぶつ","けんま","けんみん","けんめい","けんらん","けんり","こあくま","こいぬ","こいびと","ごうい","こうえん","こうおん","こうかん","ごうきゅう","ごうけい","こうこう","こうさい","こうじ","こうすい","ごうせい","こうそく","こうたい","こうちゃ","こうつう","こうてい","こうどう","こうない","こうはい","ごうほう","ごうまん","こうもく","こうりつ","こえる","こおり","ごかい","ごがつ","ごかん","こくご","こくさい","こくとう","こくない","こくはく","こぐま","こけい","こける","ここのか","こころ","こさめ","こしつ","こすう","こせい","こせき","こぜん","こそだて","こたい","こたえる","こたつ","こちょう","こっか","こつこつ","こつばん","こつぶ","こてい","こてん","ことがら","ことし","ことば","ことり","こなごな","こねこね","このまま","このみ","このよ","ごはん","こひつじ","こふう","こふん","こぼれる","ごまあぶら","こまかい","ごますり","こまつな","こまる","こむぎこ","こもじ","こもち","こもの","こもん","こやく","こやま","こゆう","こゆび","こよい","こよう","こりる","これくしょん","ころっけ","こわもて","こわれる","こんいん","こんかい","こんき","こんしゅう","こんすい","こんだて","こんとん","こんなん","こんびに","こんぽん","こんまけ","こんや","こんれい","こんわく","ざいえき","さいかい","さいきん","ざいげん","ざいこ","さいしょ","さいせい","ざいたく","ざいちゅう","さいてき","ざいりょう","さうな","さかいし","さがす","さかな","さかみち","さがる","さぎょう","さくし","さくひん","さくら","さこく","さこつ","さずかる","ざせき","さたん","さつえい","ざつおん","ざっか","ざつがく","さっきょく","ざっし","さつじん","ざっそう","さつたば","さつまいも","さてい","さといも","さとう","さとおや","さとし","さとる","さのう","さばく","さびしい","さべつ","さほう","さほど","さます","さみしい","さみだれ","さむけ","さめる","さやえんどう","さゆう","さよう","さよく","さらだ","ざるそば","さわやか","さわる","さんいん","さんか","さんきゃく","さんこう","さんさい","ざんしょ","さんすう","さんせい","さんそ","さんち","さんま","さんみ","さんらん","しあい","しあげ","しあさって","しあわせ","しいく","しいん","しうち","しえい","しおけ","しかい","しかく","じかん","しごと","しすう","じだい","したうけ","したぎ","したて","したみ","しちょう","しちりん","しっかり","しつじ","しつもん","してい","してき","してつ","じてん","じどう","しなぎれ","しなもの","しなん","しねま","しねん","しのぐ","しのぶ","しはい","しばかり","しはつ","しはらい","しはん","しひょう","しふく","じぶん","しへい","しほう","しほん","しまう","しまる","しみん","しむける","じむしょ","しめい","しめる","しもん","しゃいん","しゃうん","しゃおん","じゃがいも","しやくしょ","しゃくほう","しゃけん","しゃこ","しゃざい","しゃしん","しゃせん","しゃそう","しゃたい","しゃちょう","しゃっきん","じゃま","しゃりん","しゃれい","じゆう","じゅうしょ","しゅくはく","じゅしん","しゅっせき","しゅみ","しゅらば","じゅんばん","しょうかい","しょくたく","しょっけん","しょどう","しょもつ","しらせる","しらべる","しんか","しんこう","じんじゃ","しんせいじ","しんちく","しんりん","すあげ","すあし","すあな","ずあん","すいえい","すいか","すいとう","ずいぶん","すいようび","すうがく","すうじつ","すうせん","すおどり","すきま","すくう","すくない","すける","すごい","すこし","ずさん","すずしい","すすむ","すすめる","すっかり","ずっしり","ずっと","すてき","すてる","すねる","すのこ","すはだ","すばらしい","ずひょう","ずぶぬれ","すぶり","すふれ","すべて","すべる","ずほう","すぼん","すまい","すめし","すもう","すやき","すらすら","するめ","すれちがう","すろっと","すわる","すんぜん","すんぽう","せあぶら","せいかつ","せいげん","せいじ","せいよう","せおう","せかいかん","せきにん","せきむ","せきゆ","せきらんうん","せけん","せこう","せすじ","せたい","せたけ","せっかく","せっきゃく","ぜっく","せっけん","せっこつ","せっさたくま","せつぞく","せつだん","せつでん","せっぱん","せつび","せつぶん","せつめい","せつりつ","せなか","せのび","せはば","せびろ","せぼね","せまい","せまる","せめる","せもたれ","せりふ","ぜんあく","せんい","せんえい","せんか","せんきょ","せんく","せんげん","ぜんご","せんさい","せんしゅ","せんすい","せんせい","せんぞ","せんたく","せんちょう","せんてい","せんとう","せんぬき","せんねん","せんぱい","ぜんぶ","ぜんぽう","せんむ","せんめんじょ","せんもん","せんやく","せんゆう","せんよう","ぜんら","ぜんりゃく","せんれい","せんろ","そあく","そいとげる","そいね","そうがんきょう","そうき","そうご","そうしん","そうだん","そうなん","そうび","そうめん","そうり","そえもの","そえん","そがい","そげき","そこう","そこそこ","そざい","そしな","そせい","そせん","そそぐ","そだてる","そつう","そつえん","そっかん","そつぎょう","そっけつ","そっこう","そっせん","そっと","そとがわ","そとづら","そなえる","そなた","そふぼ","そぼく","そぼろ","そまつ","そまる","そむく","そむりえ","そめる","そもそも","そよかぜ","そらまめ","そろう","そんかい","そんけい","そんざい","そんしつ","そんぞく","そんちょう","ぞんび","ぞんぶん","そんみん","たあい","たいいん","たいうん","たいえき","たいおう","だいがく","たいき","たいぐう","たいけん","たいこ","たいざい","だいじょうぶ","だいすき","たいせつ","たいそう","だいたい","たいちょう","たいてい","だいどころ","たいない","たいねつ","たいのう","たいはん","だいひょう","たいふう","たいへん","たいほ","たいまつばな","たいみんぐ","たいむ","たいめん","たいやき","たいよう","たいら","たいりょく","たいる","たいわん","たうえ","たえる","たおす","たおる","たおれる","たかい","たかね","たきび","たくさん","たこく","たこやき","たさい","たしざん","だじゃれ","たすける","たずさわる","たそがれ","たたかう","たたく","ただしい","たたみ","たちばな","だっかい","だっきゃく","だっこ","だっしゅつ","だったい","たてる","たとえる","たなばた","たにん","たぬき","たのしみ","たはつ","たぶん","たべる","たぼう","たまご","たまる","だむる","ためいき","ためす","ためる","たもつ","たやすい","たよる","たらす","たりきほんがん","たりょう","たりる","たると","たれる","たれんと","たろっと","たわむれる","だんあつ","たんい","たんおん","たんか","たんき","たんけん","たんご","たんさん","たんじょうび","だんせい","たんそく","たんたい","だんち","たんてい","たんとう","だんな","たんにん","だんねつ","たんのう","たんぴん","だんぼう","たんまつ","たんめい","だんれつ","だんろ","だんわ","ちあい","ちあん","ちいき","ちいさい","ちえん","ちかい","ちから","ちきゅう","ちきん","ちけいず","ちけん","ちこく","ちさい","ちしき","ちしりょう","ちせい","ちそう","ちたい","ちたん","ちちおや","ちつじょ","ちてき","ちてん","ちぬき","ちぬり","ちのう","ちひょう","ちへいせん","ちほう","ちまた","ちみつ","ちみどろ","ちめいど","ちゃんこなべ","ちゅうい","ちゆりょく","ちょうし","ちょさくけん","ちらし","ちらみ","ちりがみ","ちりょう","ちるど","ちわわ","ちんたい","ちんもく","ついか","ついたち","つうか","つうじょう","つうはん","つうわ","つかう","つかれる","つくね","つくる","つけね","つける","つごう","つたえる","つづく","つつじ","つつむ","つとめる","つながる","つなみ","つねづね","つのる","つぶす","つまらない","つまる","つみき","つめたい","つもり","つもる","つよい","つるぼ","つるみく","つわもの","つわり","てあし","てあて","てあみ","ていおん","ていか","ていき","ていけい","ていこく","ていさつ","ていし","ていせい","ていたい","ていど","ていねい","ていひょう","ていへん","ていぼう","てうち","ておくれ","てきとう","てくび","でこぼこ","てさぎょう","てさげ","てすり","てそう","てちがい","てちょう","てつがく","てつづき","でっぱ","てつぼう","てつや","でぬかえ","てぬき","てぬぐい","てのひら","てはい","てぶくろ","てふだ","てほどき","てほん","てまえ","てまきずし","てみじか","てみやげ","てらす","てれび","てわけ","てわたし","でんあつ","てんいん","てんかい","てんき","てんぐ","てんけん","てんごく","てんさい","てんし","てんすう","でんち","てんてき","てんとう","てんない","てんぷら","てんぼうだい","てんめつ","てんらんかい","でんりょく","でんわ","どあい","といれ","どうかん","とうきゅう","どうぐ","とうし","とうむぎ","とおい","とおか","とおく","とおす","とおる","とかい","とかす","ときおり","ときどき","とくい","とくしゅう","とくてん","とくに","とくべつ","とけい","とける","とこや","とさか","としょかん","とそう","とたん","とちゅう","とっきゅう","とっくん","とつぜん","とつにゅう","とどける","ととのえる","とない","となえる","となり","とのさま","とばす","どぶがわ","とほう","とまる","とめる","ともだち","ともる","どようび","とらえる","とんかつ","どんぶり","ないかく","ないこう","ないしょ","ないす","ないせん","ないそう","なおす","ながい","なくす","なげる","なこうど","なさけ","なたでここ","なっとう","なつやすみ","ななおし","なにごと","なにもの","なにわ","なのか","なふだ","なまいき","なまえ","なまみ","なみだ","なめらか","なめる","なやむ","ならう","ならび","ならぶ","なれる","なわとび","なわばり","にあう","にいがた","にうけ","におい","にかい","にがて","にきび","にくしみ","にくまん","にげる","にさんかたんそ","にしき","にせもの","にちじょう","にちようび","にっか","にっき","にっけい","にっこう","にっさん","にっしょく","にっすう","にっせき","にってい","になう","にほん","にまめ","にもつ","にやり","にゅういん","にりんしゃ","にわとり","にんい","にんか","にんき","にんげん","にんしき","にんずう","にんそう","にんたい","にんち","にんてい","にんにく","にんぷ","にんまり","にんむ","にんめい","にんよう","ぬいくぎ","ぬかす","ぬぐいとる","ぬぐう","ぬくもり","ぬすむ","ぬまえび","ぬめり","ぬらす","ぬんちゃく","ねあげ","ねいき","ねいる","ねいろ","ねぐせ","ねくたい","ねくら","ねこぜ","ねこむ","ねさげ","ねすごす","ねそべる","ねだん","ねつい","ねっしん","ねつぞう","ねったいぎょ","ねぶそく","ねふだ","ねぼう","ねほりはほり","ねまき","ねまわし","ねみみ","ねむい","ねむたい","ねもと","ねらう","ねわざ","ねんいり","ねんおし","ねんかん","ねんきん","ねんぐ","ねんざ","ねんし","ねんちゃく","ねんど","ねんぴ","ねんぶつ","ねんまつ","ねんりょう","ねんれい","のいず","のおづま","のがす","のきなみ","のこぎり","のこす","のこる","のせる","のぞく","のぞむ","のたまう","のちほど","のっく","のばす","のはら","のべる","のぼる","のみもの","のやま","のらいぬ","のらねこ","のりもの","のりゆき","のれん","のんき","ばあい","はあく","ばあさん","ばいか","ばいく","はいけん","はいご","はいしん","はいすい","はいせん","はいそう","はいち","ばいばい","はいれつ","はえる","はおる","はかい","ばかり","はかる","はくしゅ","はけん","はこぶ","はさみ","はさん","はしご","ばしょ","はしる","はせる","ぱそこん","はそん","はたん","はちみつ","はつおん","はっかく","はづき","はっきり","はっくつ","はっけん","はっこう","はっさん","はっしん","はったつ","はっちゅう","はってん","はっぴょう","はっぽう","はなす","はなび","はにかむ","はぶらし","はみがき","はむかう","はめつ","はやい","はやし","はらう","はろうぃん","はわい","はんい","はんえい","はんおん","はんかく","はんきょう","ばんぐみ","はんこ","はんしゃ","はんすう","はんだん","ぱんち","ぱんつ","はんてい","はんとし","はんのう","はんぱ","はんぶん","はんぺん","はんぼうき","はんめい","はんらん","はんろん","ひいき","ひうん","ひえる","ひかく","ひかり","ひかる","ひかん","ひくい","ひけつ","ひこうき","ひこく","ひさい","ひさしぶり","ひさん","びじゅつかん","ひしょ","ひそか","ひそむ","ひたむき","ひだり","ひたる","ひつぎ","ひっこし","ひっし","ひつじゅひん","ひっす","ひつぜん","ぴったり","ぴっちり","ひつよう","ひてい","ひとごみ","ひなまつり","ひなん","ひねる","ひはん","ひびく","ひひょう","ひほう","ひまわり","ひまん","ひみつ","ひめい","ひめじし","ひやけ","ひやす","ひよう","びょうき","ひらがな","ひらく","ひりつ","ひりょう","ひるま","ひるやすみ","ひれい","ひろい","ひろう","ひろき","ひろゆき","ひんかく","ひんけつ","ひんこん","ひんしゅ","ひんそう","ぴんち","ひんぱん","びんぼう","ふあん","ふいうち","ふうけい","ふうせん","ぷうたろう","ふうとう","ふうふ","ふえる","ふおん","ふかい","ふきん","ふくざつ","ふくぶくろ","ふこう","ふさい","ふしぎ","ふじみ","ふすま","ふせい","ふせぐ","ふそく","ぶたにく","ふたん","ふちょう","ふつう","ふつか","ふっかつ","ふっき","ふっこく","ぶどう","ふとる","ふとん","ふのう","ふはい","ふひょう","ふへん","ふまん","ふみん","ふめつ","ふめん","ふよう","ふりこ","ふりる","ふるい","ふんいき","ぶんがく","ぶんぐ","ふんしつ","ぶんせき","ふんそう","ぶんぽう","へいあん","へいおん","へいがい","へいき","へいげん","へいこう","へいさ","へいしゃ","へいせつ","へいそ","へいたく","へいてん","へいねつ","へいわ","へきが","へこむ","べにいろ","べにしょうが","へらす","へんかん","べんきょう","べんごし","へんさい","へんたい","べんり","ほあん","ほいく","ぼうぎょ","ほうこく","ほうそう","ほうほう","ほうもん","ほうりつ","ほえる","ほおん","ほかん","ほきょう","ぼきん","ほくろ","ほけつ","ほけん","ほこう","ほこる","ほしい","ほしつ","ほしゅ","ほしょう","ほせい","ほそい","ほそく","ほたて","ほたる","ぽちぶくろ","ほっきょく","ほっさ","ほったん","ほとんど","ほめる","ほんい","ほんき","ほんけ","ほんしつ","ほんやく","まいにち","まかい","まかせる","まがる","まける","まこと","まさつ","まじめ","ますく","まぜる","まつり","まとめ","まなぶ","まぬけ","まねく","まほう","まもる","まゆげ","まよう","まろやか","まわす","まわり","まわる","まんが","まんきつ","まんぞく","まんなか","みいら","みうち","みえる","みがく","みかた","みかん","みけん","みこん","みじかい","みすい","みすえる","みせる","みっか","みつかる","みつける","みてい","みとめる","みなと","みなみかさい","みねらる","みのう","みのがす","みほん","みもと","みやげ","みらい","みりょく","みわく","みんか","みんぞく","むいか","むえき","むえん","むかい","むかう","むかえ","むかし","むぎちゃ","むける","むげん","むさぼる","むしあつい","むしば","むじゅん","むしろ","むすう","むすこ","むすぶ","むすめ","むせる","むせん","むちゅう","むなしい","むのう","むやみ","むよう","むらさき","むりょう","むろん","めいあん","めいうん","めいえん","めいかく","めいきょく","めいさい","めいし","めいそう","めいぶつ","めいれい","めいわく","めぐまれる","めざす","めした","めずらしい","めだつ","めまい","めやす","めんきょ","めんせき","めんどう","もうしあげる","もうどうけん","もえる","もくし","もくてき","もくようび","もちろん","もどる","もらう","もんく","もんだい","やおや","やける","やさい","やさしい","やすい","やすたろう","やすみ","やせる","やそう","やたい","やちん","やっと","やっぱり","やぶる","やめる","ややこしい","やよい","やわらかい","ゆうき","ゆうびんきょく","ゆうべ","ゆうめい","ゆけつ","ゆしゅつ","ゆせん","ゆそう","ゆたか","ゆちゃく","ゆでる","ゆにゅう","ゆびわ","ゆらい","ゆれる","ようい","ようか","ようきゅう","ようじ","ようす","ようちえん","よかぜ","よかん","よきん","よくせい","よくぼう","よけい","よごれる","よさん","よしゅう","よそう","よそく","よっか","よてい","よどがわく","よねつ","よやく","よゆう","よろこぶ","よろしい","らいう","らくがき","らくご","らくさつ","らくだ","らしんばん","らせん","らぞく","らたい","らっか","られつ","りえき","りかい","りきさく","りきせつ","りくぐん","りくつ","りけん","りこう","りせい","りそう","りそく","りてん","りねん","りゆう","りゅうがく","りよう","りょうり","りょかん","りょくちゃ","りょこう","りりく","りれき","りろん","りんご","るいけい","るいさい","るいじ","るいせき","るすばん","るりがわら","れいかん","れいぎ","れいせい","れいぞうこ","れいとう","れいぼう","れきし","れきだい","れんあい","れんけい","れんこん","れんさい","れんしゅう","れんぞく","れんらく","ろうか","ろうご","ろうじん","ろうそく","ろくが","ろこつ","ろじうら","ろしゅつ","ろせん","ろてん","ろめん","ろれつ","ろんぎ","ろんぱ","ろんぶん","ろんり","わかす","わかめ","わかやま","わかれる","わしつ","わじまし","わすれもの","わらう","われる"]'), Xl = /* @__PURE__ */ JSON.parse('["abacate","abaixo","abalar","abater","abduzir","abelha","aberto","abismo","abotoar","abranger","abreviar","abrigar","abrupto","absinto","absoluto","absurdo","abutre","acabado","acalmar","acampar","acanhar","acaso","aceitar","acelerar","acenar","acervo","acessar","acetona","achatar","acidez","acima","acionado","acirrar","aclamar","aclive","acolhida","acomodar","acoplar","acordar","acumular","acusador","adaptar","adega","adentro","adepto","adequar","aderente","adesivo","adeus","adiante","aditivo","adjetivo","adjunto","admirar","adorar","adquirir","adubo","adverso","advogado","aeronave","afastar","aferir","afetivo","afinador","afivelar","aflito","afluente","afrontar","agachar","agarrar","agasalho","agenciar","agilizar","agiota","agitado","agora","agradar","agreste","agrupar","aguardar","agulha","ajoelhar","ajudar","ajustar","alameda","alarme","alastrar","alavanca","albergue","albino","alcatra","aldeia","alecrim","alegria","alertar","alface","alfinete","algum","alheio","aliar","alicate","alienar","alinhar","aliviar","almofada","alocar","alpiste","alterar","altitude","alucinar","alugar","aluno","alusivo","alvo","amaciar","amador","amarelo","amassar","ambas","ambiente","ameixa","amenizar","amido","amistoso","amizade","amolador","amontoar","amoroso","amostra","amparar","ampliar","ampola","anagrama","analisar","anarquia","anatomia","andaime","anel","anexo","angular","animar","anjo","anomalia","anotado","ansioso","anterior","anuidade","anunciar","anzol","apagador","apalpar","apanhado","apego","apelido","apertada","apesar","apetite","apito","aplauso","aplicada","apoio","apontar","aposta","aprendiz","aprovar","aquecer","arame","aranha","arara","arcada","ardente","areia","arejar","arenito","aresta","argiloso","argola","arma","arquivo","arraial","arrebate","arriscar","arroba","arrumar","arsenal","arterial","artigo","arvoredo","asfaltar","asilado","aspirar","assador","assinar","assoalho","assunto","astral","atacado","atadura","atalho","atarefar","atear","atender","aterro","ateu","atingir","atirador","ativo","atoleiro","atracar","atrevido","atriz","atual","atum","auditor","aumentar","aura","aurora","autismo","autoria","autuar","avaliar","avante","avaria","avental","avesso","aviador","avisar","avulso","axila","azarar","azedo","azeite","azulejo","babar","babosa","bacalhau","bacharel","bacia","bagagem","baiano","bailar","baioneta","bairro","baixista","bajular","baleia","baliza","balsa","banal","bandeira","banho","banir","banquete","barato","barbado","baronesa","barraca","barulho","baseado","bastante","batata","batedor","batida","batom","batucar","baunilha","beber","beijo","beirada","beisebol","beldade","beleza","belga","beliscar","bendito","bengala","benzer","berimbau","berlinda","berro","besouro","bexiga","bezerro","bico","bicudo","bienal","bifocal","bifurcar","bigorna","bilhete","bimestre","bimotor","biologia","biombo","biosfera","bipolar","birrento","biscoito","bisneto","bispo","bissexto","bitola","bizarro","blindado","bloco","bloquear","boato","bobagem","bocado","bocejo","bochecha","boicotar","bolada","boletim","bolha","bolo","bombeiro","bonde","boneco","bonita","borbulha","borda","boreal","borracha","bovino","boxeador","branco","brasa","braveza","breu","briga","brilho","brincar","broa","brochura","bronzear","broto","bruxo","bucha","budismo","bufar","bule","buraco","busca","busto","buzina","cabana","cabelo","cabide","cabo","cabrito","cacau","cacetada","cachorro","cacique","cadastro","cadeado","cafezal","caiaque","caipira","caixote","cajado","caju","calafrio","calcular","caldeira","calibrar","calmante","calota","camada","cambista","camisa","camomila","campanha","camuflar","canavial","cancelar","caneta","canguru","canhoto","canivete","canoa","cansado","cantar","canudo","capacho","capela","capinar","capotar","capricho","captador","capuz","caracol","carbono","cardeal","careca","carimbar","carneiro","carpete","carreira","cartaz","carvalho","casaco","casca","casebre","castelo","casulo","catarata","cativar","caule","causador","cautelar","cavalo","caverna","cebola","cedilha","cegonha","celebrar","celular","cenoura","censo","centeio","cercar","cerrado","certeiro","cerveja","cetim","cevada","chacota","chaleira","chamado","chapada","charme","chatice","chave","chefe","chegada","cheiro","cheque","chicote","chifre","chinelo","chocalho","chover","chumbo","chutar","chuva","cicatriz","ciclone","cidade","cidreira","ciente","cigana","cimento","cinto","cinza","ciranda","circuito","cirurgia","citar","clareza","clero","clicar","clone","clube","coado","coagir","cobaia","cobertor","cobrar","cocada","coelho","coentro","coeso","cogumelo","coibir","coifa","coiote","colar","coleira","colher","colidir","colmeia","colono","coluna","comando","combinar","comentar","comitiva","comover","complexo","comum","concha","condor","conectar","confuso","congelar","conhecer","conjugar","consumir","contrato","convite","cooperar","copeiro","copiador","copo","coquetel","coragem","cordial","corneta","coronha","corporal","correio","cortejo","coruja","corvo","cosseno","costela","cotonete","couro","couve","covil","cozinha","cratera","cravo","creche","credor","creme","crer","crespo","criada","criminal","crioulo","crise","criticar","crosta","crua","cruzeiro","cubano","cueca","cuidado","cujo","culatra","culminar","culpar","cultura","cumprir","cunhado","cupido","curativo","curral","cursar","curto","cuspir","custear","cutelo","damasco","datar","debater","debitar","deboche","debulhar","decalque","decimal","declive","decote","decretar","dedal","dedicado","deduzir","defesa","defumar","degelo","degrau","degustar","deitado","deixar","delator","delegado","delinear","delonga","demanda","demitir","demolido","dentista","depenado","depilar","depois","depressa","depurar","deriva","derramar","desafio","desbotar","descanso","desenho","desfiado","desgaste","desigual","deslize","desmamar","desova","despesa","destaque","desviar","detalhar","detentor","detonar","detrito","deusa","dever","devido","devotado","dezena","diagrama","dialeto","didata","difuso","digitar","dilatado","diluente","diminuir","dinastia","dinheiro","diocese","direto","discreta","disfarce","disparo","disquete","dissipar","distante","ditador","diurno","diverso","divisor","divulgar","dizer","dobrador","dolorido","domador","dominado","donativo","donzela","dormente","dorsal","dosagem","dourado","doutor","drenagem","drible","drogaria","duelar","duende","dueto","duplo","duquesa","durante","duvidoso","eclodir","ecoar","ecologia","edificar","edital","educado","efeito","efetivar","ejetar","elaborar","eleger","eleitor","elenco","elevador","eliminar","elogiar","embargo","embolado","embrulho","embutido","emenda","emergir","emissor","empatia","empenho","empinado","empolgar","emprego","empurrar","emulador","encaixe","encenado","enchente","encontro","endeusar","endossar","enfaixar","enfeite","enfim","engajado","engenho","englobar","engomado","engraxar","enguia","enjoar","enlatar","enquanto","enraizar","enrolado","enrugar","ensaio","enseada","ensino","ensopado","entanto","enteado","entidade","entortar","entrada","entulho","envergar","enviado","envolver","enxame","enxerto","enxofre","enxuto","epiderme","equipar","ereto","erguido","errata","erva","ervilha","esbanjar","esbelto","escama","escola","escrita","escuta","esfinge","esfolar","esfregar","esfumado","esgrima","esmalte","espanto","espelho","espiga","esponja","espreita","espumar","esquerda","estaca","esteira","esticar","estofado","estrela","estudo","esvaziar","etanol","etiqueta","euforia","europeu","evacuar","evaporar","evasivo","eventual","evidente","evoluir","exagero","exalar","examinar","exato","exausto","excesso","excitar","exclamar","executar","exemplo","exibir","exigente","exonerar","expandir","expelir","expirar","explanar","exposto","expresso","expulsar","externo","extinto","extrato","fabricar","fabuloso","faceta","facial","fada","fadiga","faixa","falar","falta","familiar","fandango","fanfarra","fantoche","fardado","farelo","farinha","farofa","farpa","fartura","fatia","fator","favorita","faxina","fazenda","fechado","feijoada","feirante","felino","feminino","fenda","feno","fera","feriado","ferrugem","ferver","festejar","fetal","feudal","fiapo","fibrose","ficar","ficheiro","figurado","fileira","filho","filme","filtrar","firmeza","fisgada","fissura","fita","fivela","fixador","fixo","flacidez","flamingo","flanela","flechada","flora","flutuar","fluxo","focal","focinho","fofocar","fogo","foguete","foice","folgado","folheto","forjar","formiga","forno","forte","fosco","fossa","fragata","fralda","frango","frasco","fraterno","freira","frente","fretar","frieza","friso","fritura","fronha","frustrar","fruteira","fugir","fulano","fuligem","fundar","fungo","funil","furador","furioso","futebol","gabarito","gabinete","gado","gaiato","gaiola","gaivota","galega","galho","galinha","galocha","ganhar","garagem","garfo","gargalo","garimpo","garoupa","garrafa","gasoduto","gasto","gata","gatilho","gaveta","gazela","gelado","geleia","gelo","gemada","gemer","gemido","generoso","gengiva","genial","genoma","genro","geologia","gerador","germinar","gesso","gestor","ginasta","gincana","gingado","girafa","girino","glacial","glicose","global","glorioso","goela","goiaba","golfe","golpear","gordura","gorjeta","gorro","gostoso","goteira","governar","gracejo","gradual","grafite","gralha","grampo","granada","gratuito","graveto","graxa","grego","grelhar","greve","grilo","grisalho","gritaria","grosso","grotesco","grudado","grunhido","gruta","guache","guarani","guaxinim","guerrear","guiar","guincho","guisado","gula","guloso","guru","habitar","harmonia","haste","haver","hectare","herdar","heresia","hesitar","hiato","hibernar","hidratar","hiena","hino","hipismo","hipnose","hipoteca","hoje","holofote","homem","honesto","honrado","hormonal","hospedar","humorado","iate","ideia","idoso","ignorado","igreja","iguana","ileso","ilha","iludido","iluminar","ilustrar","imagem","imediato","imenso","imersivo","iminente","imitador","imortal","impacto","impedir","implante","impor","imprensa","impune","imunizar","inalador","inapto","inativo","incenso","inchar","incidir","incluir","incolor","indeciso","indireto","indutor","ineficaz","inerente","infantil","infestar","infinito","inflamar","informal","infrator","ingerir","inibido","inicial","inimigo","injetar","inocente","inodoro","inovador","inox","inquieto","inscrito","inseto","insistir","inspetor","instalar","insulto","intacto","integral","intimar","intocado","intriga","invasor","inverno","invicto","invocar","iogurte","iraniano","ironizar","irreal","irritado","isca","isento","isolado","isqueiro","italiano","janeiro","jangada","janta","jararaca","jardim","jarro","jasmim","jato","javali","jazida","jejum","joaninha","joelhada","jogador","joia","jornal","jorrar","jovem","juba","judeu","judoca","juiz","julgador","julho","jurado","jurista","juro","justa","labareda","laboral","lacre","lactante","ladrilho","lagarta","lagoa","laje","lamber","lamentar","laminar","lampejo","lanche","lapidar","lapso","laranja","lareira","largura","lasanha","lastro","lateral","latido","lavanda","lavoura","lavrador","laxante","lazer","lealdade","lebre","legado","legendar","legista","leigo","leiloar","leitura","lembrete","leme","lenhador","lentilha","leoa","lesma","leste","letivo","letreiro","levar","leveza","levitar","liberal","libido","liderar","ligar","ligeiro","limitar","limoeiro","limpador","linda","linear","linhagem","liquidez","listagem","lisura","litoral","livro","lixa","lixeira","locador","locutor","lojista","lombo","lona","longe","lontra","lorde","lotado","loteria","loucura","lousa","louvar","luar","lucidez","lucro","luneta","lustre","lutador","luva","macaco","macete","machado","macio","madeira","madrinha","magnata","magreza","maior","mais","malandro","malha","malote","maluco","mamilo","mamoeiro","mamute","manada","mancha","mandato","manequim","manhoso","manivela","manobrar","mansa","manter","manusear","mapeado","maquinar","marcador","maresia","marfim","margem","marinho","marmita","maroto","marquise","marreco","martelo","marujo","mascote","masmorra","massagem","mastigar","matagal","materno","matinal","matutar","maxilar","medalha","medida","medusa","megafone","meiga","melancia","melhor","membro","memorial","menino","menos","mensagem","mental","merecer","mergulho","mesada","mesclar","mesmo","mesquita","mestre","metade","meteoro","metragem","mexer","mexicano","micro","migalha","migrar","milagre","milenar","milhar","mimado","minerar","minhoca","ministro","minoria","miolo","mirante","mirtilo","misturar","mocidade","moderno","modular","moeda","moer","moinho","moita","moldura","moleza","molho","molinete","molusco","montanha","moqueca","morango","morcego","mordomo","morena","mosaico","mosquete","mostarda","motel","motim","moto","motriz","muda","muito","mulata","mulher","multar","mundial","munido","muralha","murcho","muscular","museu","musical","nacional","nadador","naja","namoro","narina","narrado","nascer","nativa","natureza","navalha","navegar","navio","neblina","nebuloso","negativa","negociar","negrito","nervoso","neta","neural","nevasca","nevoeiro","ninar","ninho","nitidez","nivelar","nobreza","noite","noiva","nomear","nominal","nordeste","nortear","notar","noticiar","noturno","novelo","novilho","novo","nublado","nudez","numeral","nupcial","nutrir","nuvem","obcecado","obedecer","objetivo","obrigado","obscuro","obstetra","obter","obturar","ocidente","ocioso","ocorrer","oculista","ocupado","ofegante","ofensiva","oferenda","oficina","ofuscado","ogiva","olaria","oleoso","olhar","oliveira","ombro","omelete","omisso","omitir","ondulado","oneroso","ontem","opcional","operador","oponente","oportuno","oposto","orar","orbitar","ordem","ordinal","orfanato","orgasmo","orgulho","oriental","origem","oriundo","orla","ortodoxo","orvalho","oscilar","ossada","osso","ostentar","otimismo","ousadia","outono","outubro","ouvido","ovelha","ovular","oxidar","oxigenar","pacato","paciente","pacote","pactuar","padaria","padrinho","pagar","pagode","painel","pairar","paisagem","palavra","palestra","palheta","palito","palmada","palpitar","pancada","panela","panfleto","panqueca","pantanal","papagaio","papelada","papiro","parafina","parcial","pardal","parede","partida","pasmo","passado","pastel","patamar","patente","patinar","patrono","paulada","pausar","peculiar","pedalar","pedestre","pediatra","pedra","pegada","peitoral","peixe","pele","pelicano","penca","pendurar","peneira","penhasco","pensador","pente","perceber","perfeito","pergunta","perito","permitir","perna","perplexo","persiana","pertence","peruca","pescado","pesquisa","pessoa","petiscar","piada","picado","piedade","pigmento","pilastra","pilhado","pilotar","pimenta","pincel","pinguim","pinha","pinote","pintar","pioneiro","pipoca","piquete","piranha","pires","pirueta","piscar","pistola","pitanga","pivete","planta","plaqueta","platina","plebeu","plumagem","pluvial","pneu","poda","poeira","poetisa","polegada","policiar","poluente","polvilho","pomar","pomba","ponderar","pontaria","populoso","porta","possuir","postal","pote","poupar","pouso","povoar","praia","prancha","prato","praxe","prece","predador","prefeito","premiar","prensar","preparar","presilha","pretexto","prevenir","prezar","primata","princesa","prisma","privado","processo","produto","profeta","proibido","projeto","prometer","propagar","prosa","protetor","provador","publicar","pudim","pular","pulmonar","pulseira","punhal","punir","pupilo","pureza","puxador","quadra","quantia","quarto","quase","quebrar","queda","queijo","quente","querido","quimono","quina","quiosque","rabanada","rabisco","rachar","racionar","radial","raiar","rainha","raio","raiva","rajada","ralado","ramal","ranger","ranhura","rapadura","rapel","rapidez","raposa","raquete","raridade","rasante","rascunho","rasgar","raspador","rasteira","rasurar","ratazana","ratoeira","realeza","reanimar","reaver","rebaixar","rebelde","rebolar","recado","recente","recheio","recibo","recordar","recrutar","recuar","rede","redimir","redonda","reduzida","reenvio","refinar","refletir","refogar","refresco","refugiar","regalia","regime","regra","reinado","reitor","rejeitar","relativo","remador","remendo","remorso","renovado","reparo","repelir","repleto","repolho","represa","repudiar","requerer","resenha","resfriar","resgatar","residir","resolver","respeito","ressaca","restante","resumir","retalho","reter","retirar","retomada","retratar","revelar","revisor","revolta","riacho","rica","rigidez","rigoroso","rimar","ringue","risada","risco","risonho","robalo","rochedo","rodada","rodeio","rodovia","roedor","roleta","romano","roncar","rosado","roseira","rosto","rota","roteiro","rotina","rotular","rouco","roupa","roxo","rubro","rugido","rugoso","ruivo","rumo","rupestre","russo","sabor","saciar","sacola","sacudir","sadio","safira","saga","sagrada","saibro","salada","saleiro","salgado","saliva","salpicar","salsicha","saltar","salvador","sambar","samurai","sanar","sanfona","sangue","sanidade","sapato","sarda","sargento","sarjeta","saturar","saudade","saxofone","sazonal","secar","secular","seda","sedento","sediado","sedoso","sedutor","segmento","segredo","segundo","seiva","seleto","selvagem","semanal","semente","senador","senhor","sensual","sentado","separado","sereia","seringa","serra","servo","setembro","setor","sigilo","silhueta","silicone","simetria","simpatia","simular","sinal","sincero","singular","sinopse","sintonia","sirene","siri","situado","soberano","sobra","socorro","sogro","soja","solda","soletrar","solteiro","sombrio","sonata","sondar","sonegar","sonhador","sono","soprano","soquete","sorrir","sorteio","sossego","sotaque","soterrar","sovado","sozinho","suavizar","subida","submerso","subsolo","subtrair","sucata","sucesso","suco","sudeste","sufixo","sugador","sugerir","sujeito","sulfato","sumir","suor","superior","suplicar","suposto","suprimir","surdina","surfista","surpresa","surreal","surtir","suspiro","sustento","tabela","tablete","tabuada","tacho","tagarela","talher","talo","talvez","tamanho","tamborim","tampa","tangente","tanto","tapar","tapioca","tardio","tarefa","tarja","tarraxa","tatuagem","taurino","taxativo","taxista","teatral","tecer","tecido","teclado","tedioso","teia","teimar","telefone","telhado","tempero","tenente","tensor","tentar","termal","terno","terreno","tese","tesoura","testado","teto","textura","texugo","tiara","tigela","tijolo","timbrar","timidez","tingido","tinteiro","tiragem","titular","toalha","tocha","tolerar","tolice","tomada","tomilho","tonel","tontura","topete","tora","torcido","torneio","torque","torrada","torto","tostar","touca","toupeira","toxina","trabalho","tracejar","tradutor","trafegar","trajeto","trama","trancar","trapo","traseiro","tratador","travar","treino","tremer","trepidar","trevo","triagem","tribo","triciclo","tridente","trilogia","trindade","triplo","triturar","triunfal","trocar","trombeta","trova","trunfo","truque","tubular","tucano","tudo","tulipa","tupi","turbo","turma","turquesa","tutelar","tutorial","uivar","umbigo","unha","unidade","uniforme","urologia","urso","urtiga","urubu","usado","usina","usufruir","vacina","vadiar","vagaroso","vaidoso","vala","valente","validade","valores","vantagem","vaqueiro","varanda","vareta","varrer","vascular","vasilha","vassoura","vazar","vazio","veado","vedar","vegetar","veicular","veleiro","velhice","veludo","vencedor","vendaval","venerar","ventre","verbal","verdade","vereador","vergonha","vermelho","verniz","versar","vertente","vespa","vestido","vetorial","viaduto","viagem","viajar","viatura","vibrador","videira","vidraria","viela","viga","vigente","vigiar","vigorar","vilarejo","vinco","vinheta","vinil","violeta","virada","virtude","visitar","visto","vitral","viveiro","vizinho","voador","voar","vogal","volante","voleibol","voltagem","volumoso","vontade","vulto","vuvuzela","xadrez","xarope","xeque","xeretar","xerife","xingar","zangado","zarpar","zebu","zelador","zombar","zoologia","zumbido"]'), Zl = /* @__PURE__ */ JSON.parse('["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual","adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor","army","around","arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction","audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake","aware","away","awesome","awful","awkward","axis","baby","bachelor","bacon","badge","bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain","barrel","base","basic","basket","battle","beach","bean","beauty","because","become","beef","before","begin","behave","behind","believe","below","belt","bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike","bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless","blind","blood","blossom","blouse","blue","blur","blush","board","boat","body","boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain","brand","brass","brave","bread","breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb","bulk","bullet","bundle","bunker","burden","burger","burst","bus","business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp","can","canal","cancel","candy","cannon","canoe","canvas","canyon","capable","capital","captain","car","carbon","card","cargo","carpet","carry","cart","case","cash","casino","castle","casual","cat","catalog","catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century","cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase","chat","cheap","check","cheese","chef","cherry","chest","chicken","chief","child","chimney","choice","choose","chronic","chuckle","chunk","churn","cigar","cinnamon","circle","citizen","city","civil","claim","clap","clarify","claw","clay","clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock","clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut","code","coffee","coil","coin","collect","color","column","combine","come","comfort","comic","common","company","concert","conduct","confirm","congress","connect","consider","control","convince","cook","cool","copper","copy","coral","core","corn","correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crouch","crowd","crucial","cruel","cruise","crumble","crunch","crush","cry","crystal","cube","culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal","debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense","define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk","despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance","divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf","dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo","ecology","economy","edge","edit","educate","effort","egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact","end","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough","enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip","era","erase","erode","erosion","error","erupt","escape","essay","essence","estate","eternal","ethics","evidence","evil","evoke","evolve","exact","example","excess","exchange","excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist","exit","exotic","expand","expect","expire","explain","expose","express","extend","extra","eye","eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame","family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father","fatigue","fault","favorite","feature","february","federal","fee","feed","feel","female","fence","festival","fetch","fever","few","fiber","fiction","field","figure","file","film","filter","final","find","fine","finger","finish","fire","firm","first","fiscal","fish","fit","fitness","fix","flag","flame","flash","flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid","flush","fly","foam","focus","fog","foil","fold","follow","food","foot","force","forest","forget","fork","fortune","forum","forward","fossil","foster","found","fox","fragile","frame","frequent","fresh","friend","fringe","frog","front","frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic","garment","gas","gasp","gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue","goat","goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown","grab","grace","grain","grant","grape","grass","gravity","great","green","grid","grief","grit","grocery","group","grow","grunt","guard","guess","guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy","harbor","hard","harsh","harvest","hat","have","hawk","hazard","head","health","heart","heavy","hedgehog","height","hello","helmet","help","hen","hero","hidden","high","hill","hint","hip","hire","history","hobby","hockey","hold","hole","holiday","hollow","home","honey","hood","hope","horn","horror","horse","hospital","host","hotel","hour","hover","hub","huge","human","humble","humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","idea","identify","idle","ignore","ill","illegal","illness","image","imitate","immense","immune","impact","impose","improve","impulse","inch","include","income","increase","index","indicate","indoor","industry","infant","inflict","inform","inhale","inherit","initial","inject","injury","inmate","inner","innocent","input","inquiry","insane","insect","inside","inspire","install","intact","interest","into","invest","invite","involve","iron","island","isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel","job","join","joke","journey","joy","judge","juice","jump","jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee","knife","knock","know","lab","label","labor","ladder","lady","lake","lamp","language","laptop","large","later","latin","laugh","laundry","lava","law","lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left","leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level","liar","liberty","library","license","life","lift","light","like","limb","limit","link","lion","liquid","list","little","live","lizard","load","loan","lobster","local","lock","logic","lonely","long","loop","lottery","loud","lounge","love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine","mad","magic","magnet","maid","mail","main","major","make","mammal","man","manage","mandate","mango","mansion","manual","maple","marble","march","margin","marine","market","marriage","mask","mass","master","match","material","math","matrix","matter","maximum","maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt","member","memory","mention","menu","mercy","merge","merit","merry","mesh","message","metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor","minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile","model","modify","mom","moment","monitor","monkey","monster","month","moon","moral","more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie","much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual","myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature","near","neck","need","negative","neglect","neither","nephew","nerve","nest","net","network","neutral","never","news","next","nice","night","noble","noise","nominee","noodle","normal","north","nose","notable","note","nothing","notice","novel","now","nuclear","number","nurse","nut","oak","obey","object","oblige","obscure","observe","obtain","obvious","occur","ocean","october","odor","off","offer","office","often","oil","okay","old","olive","olympic","omit","once","one","onion","online","only","open","opera","opinion","oppose","option","orange","orbit","orchard","order","ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output","outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact","paddle","page","pair","palace","palm","panda","panel","panic","panther","paper","parade","parent","park","parrot","party","pass","patch","path","patient","patrol","pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen","penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot","pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate","play","please","pledge","pluck","plug","plunge","poem","poet","point","polar","pole","police","pond","pony","pool","popular","portion","position","possible","post","potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority","prison","private","prize","problem","process","produce","profit","program","project","promote","proof","property","prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin","punch","pupil","puppy","purchase","purity","purpose","purse","push","put","puzzle","pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio","rail","rain","raise","rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven","raw","razor","ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle","reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release","relief","rely","remain","remember","remind","remove","render","renew","rent","reopen","repair","repeat","replace","report","require","rescue","resemble","resist","resource","response","result","retire","retreat","return","reunion","reveal","review","reward","rhythm","rib","ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot","ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket","romance","roof","rookie","room","rose","rotate","rough","round","route","royal","rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness","safe","sail","salad","salmon","salon","salt","salute","same","sample","sand","satisfy","satoshi","sauce","sausage","save","say","scale","scan","scare","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script","scrub","sea","search","season","seat","second","secret","section","security","seed","seek","segment","select","sell","seminar","senior","sense","sentence","series","service","session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop","short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side","siege","sight","sign","silent","silk","silly","silver","similar","simple","since","sing","siren","sister","situate","six","size","skate","sketch","ski","skill","skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight","slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda","soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry","sort","soul","sound","soup","source","south","space","spare","spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider","spike","spin","spirit","split","spoil","sponsor","spoon","sport","spot","spray","spread","spring","spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp","stand","start","state","stay","steak","steel","stem","step","stereo","stick","still","sting","stock","stomach","stone","stool","story","stove","strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny","sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey","suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swift","swim","swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag","tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term","test","text","thank","that","theme","then","theory","there","they","thing","this","thought","three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber","time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler","toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool","tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist","toward","tower","town","toy","track","trade","traffic","tragic","train","transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick","trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust","truth","try","tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle","twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella","unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform","unique","unit","universe","unknown","unlock","until","unusual","unveil","update","upgrade","uphold","upon","upper","upset","urban","urge","usage","use","used","useful","useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","verify","version","very","vessel","veteran","viable","vibrant","vicious","victory","video","view","village","vintage","violin","virtual","virus","visa","visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash","wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather","web","wedding","weekend","weird","welcome","west","wet","whale","what","wheat","wheel","when","where","whip","whisper","wide","width","wife","wild","will","win","window","wine","wing","wink","winner","winter","wire","wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word","work","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year","yellow","you","young","youth","zebra","zero","zone","zoo"]');
var Ko;
function qo() {
  if (Ko) return Ot;
  Ko = 1, Object.defineProperty(Ot, "__esModule", { value: !0 });
  const r = {};
  Ot.wordlists = r;
  let e;
  Ot._default = e;
  try {
    Ot._default = e = ql, r.czech = e;
  } catch {
  }
  try {
    Ot._default = e = Dl, r.chinese_simplified = e;
  } catch {
  }
  try {
    Ot._default = e = Hl, r.chinese_traditional = e;
  } catch {
  }
  try {
    Ot._default = e = Vl, r.korean = e;
  } catch {
  }
  try {
    Ot._default = e = Gl, r.french = e;
  } catch {
  }
  try {
    Ot._default = e = Wl, r.italian = e;
  } catch {
  }
  try {
    Ot._default = e = Jl, r.spanish = e;
  } catch {
  }
  try {
    Ot._default = e = Yl, r.japanese = e, r.JA = e;
  } catch {
  }
  try {
    Ot._default = e = Xl, r.portuguese = e;
  } catch {
  }
  try {
    Ot._default = e = Zl, r.english = e, r.EN = e;
  } catch {
  }
  return Ot;
}
var Do;
function Ql() {
  if (Do) return Lt;
  Do = 1, Object.defineProperty(Lt, "__esModule", { value: !0 });
  const r = Ml, e = Fl, t = jl, i = Kl, o = qo();
  let a = o._default;
  const p = "Invalid mnemonic", c = "Invalid entropy", g = "Invalid mnemonic checksum", h = `A wordlist is required but a default could not be found.
Please pass a 2048 word array explicitly.`;
  function m(K) {
    return (K || "").normalize("NFKD");
  }
  function S(K, G, z) {
    for (; K.length < z; )
      K = G + K;
    return K;
  }
  function M(K) {
    return parseInt(K, 2);
  }
  function I(K) {
    return K.map((G) => S(G.toString(2), "0", 8)).join("");
  }
  function _(K) {
    const z = K.length * 8 / 32, f = r.sha256(Uint8Array.from(K));
    return I(Array.from(f)).slice(0, z);
  }
  function E(K) {
    return "mnemonic" + (K || "");
  }
  function O(K, G) {
    const z = Uint8Array.from(Buffer.from(m(K), "utf8")), f = Uint8Array.from(Buffer.from(E(m(G)), "utf8")), u = t.pbkdf2(e.sha512, z, f, {
      c: 2048,
      dkLen: 64
    });
    return Buffer.from(u);
  }
  Lt.mnemonicToSeedSync = O;
  function N(K, G) {
    const z = Uint8Array.from(Buffer.from(m(K), "utf8")), f = Uint8Array.from(Buffer.from(E(m(G)), "utf8"));
    return t.pbkdf2Async(e.sha512, z, f, {
      c: 2048,
      dkLen: 64
    }).then((u) => Buffer.from(u));
  }
  Lt.mnemonicToSeed = N;
  function U(K, G) {
    if (G = G || a, !G)
      throw new Error(h);
    const z = m(K).split(" ");
    if (z.length % 3 !== 0)
      throw new Error(p);
    const f = z.map((k) => {
      const l = G.indexOf(k);
      if (l === -1)
        throw new Error(p);
      return S(l.toString(2), "0", 11);
    }).join(""), u = Math.floor(f.length / 33) * 32, n = f.slice(0, u), s = f.slice(u), d = n.match(/(.{1,8})/g).map(M);
    if (d.length < 16)
      throw new Error(c);
    if (d.length > 32)
      throw new Error(c);
    if (d.length % 4 !== 0)
      throw new Error(c);
    const w = Buffer.from(d);
    if (_(w) !== s)
      throw new Error(g);
    return w.toString("hex");
  }
  Lt.mnemonicToEntropy = U;
  function j(K, G) {
    if (Buffer.isBuffer(K) || (K = Buffer.from(K, "hex")), G = G || a, !G)
      throw new Error(h);
    if (K.length < 16)
      throw new TypeError(c);
    if (K.length > 32)
      throw new TypeError(c);
    if (K.length % 4 !== 0)
      throw new TypeError(c);
    const z = I(Array.from(K)), f = _(K), s = (z + f).match(/(.{1,11})/g).map((d) => {
      const w = M(d);
      return G[w];
    });
    return G[0] === "あいこくしん" ? s.join("　") : s.join(" ");
  }
  Lt.entropyToMnemonic = j;
  function F(K, G, z) {
    if (K = K || 128, K % 32 !== 0)
      throw new TypeError(c);
    return G = G || ((f) => Buffer.from(i.randomBytes(f))), j(G(K / 8), z);
  }
  Lt.generateMnemonic = F;
  function C(K, G) {
    try {
      U(K, G);
    } catch {
      return !1;
    }
    return !0;
  }
  Lt.validateMnemonic = C;
  function q(K) {
    const G = o.wordlists[K];
    if (G)
      a = G;
    else
      throw new Error('Could not find wordlist for language "' + K + '"');
  }
  Lt.setDefaultWordlist = q;
  function V() {
    if (!a)
      throw new Error("No Default Wordlist set");
    return Object.keys(o.wordlists).filter((K) => K === "JA" || K === "EN" ? !1 : o.wordlists[K].every((G, z) => G === a[z]))[0];
  }
  Lt.getDefaultWordlist = V;
  var Z = qo();
  return Lt.wordlists = Z.wordlists, Lt;
}
var Vr = Ql(), wi = { exports: {} }, Sa, Ho;
function $l() {
  if (Ho) return Sa;
  Ho = 1;
  var r = 1e3, e = r * 60, t = e * 60, i = t * 24, o = i * 7, a = i * 365.25;
  Sa = function(m, S) {
    S = S || {};
    var M = typeof m;
    if (M === "string" && m.length > 0)
      return p(m);
    if (M === "number" && isFinite(m))
      return S.long ? g(m) : c(m);
    throw new Error(
      "val is not a non-empty string or a valid number. val=" + JSON.stringify(m)
    );
  };
  function p(m) {
    if (m = String(m), !(m.length > 100)) {
      var S = /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(
        m
      );
      if (S) {
        var M = parseFloat(S[1]), I = (S[2] || "ms").toLowerCase();
        switch (I) {
          case "years":
          case "year":
          case "yrs":
          case "yr":
          case "y":
            return M * a;
          case "weeks":
          case "week":
          case "w":
            return M * o;
          case "days":
          case "day":
          case "d":
            return M * i;
          case "hours":
          case "hour":
          case "hrs":
          case "hr":
          case "h":
            return M * t;
          case "minutes":
          case "minute":
          case "mins":
          case "min":
          case "m":
            return M * e;
          case "seconds":
          case "second":
          case "secs":
          case "sec":
          case "s":
            return M * r;
          case "milliseconds":
          case "millisecond":
          case "msecs":
          case "msec":
          case "ms":
            return M;
          default:
            return;
        }
      }
    }
  }
  function c(m) {
    var S = Math.abs(m);
    return S >= i ? Math.round(m / i) + "d" : S >= t ? Math.round(m / t) + "h" : S >= e ? Math.round(m / e) + "m" : S >= r ? Math.round(m / r) + "s" : m + "ms";
  }
  function g(m) {
    var S = Math.abs(m);
    return S >= i ? h(m, S, i, "day") : S >= t ? h(m, S, t, "hour") : S >= e ? h(m, S, e, "minute") : S >= r ? h(m, S, r, "second") : m + " ms";
  }
  function h(m, S, M, I) {
    var _ = S >= M * 1.5;
    return Math.round(m / M) + " " + I + (_ ? "s" : "");
  }
  return Sa;
}
var Aa, Vo;
function eh() {
  if (Vo) return Aa;
  Vo = 1;
  function r(e) {
    i.debug = i, i.default = i, i.coerce = h, i.disable = c, i.enable = a, i.enabled = g, i.humanize = $l(), i.destroy = m, Object.keys(e).forEach((S) => {
      i[S] = e[S];
    }), i.names = [], i.skips = [], i.formatters = {};
    function t(S) {
      let M = 0;
      for (let I = 0; I < S.length; I++)
        M = (M << 5) - M + S.charCodeAt(I), M |= 0;
      return i.colors[Math.abs(M) % i.colors.length];
    }
    i.selectColor = t;
    function i(S) {
      let M, I = null, _, E;
      function O(...N) {
        if (!O.enabled)
          return;
        const U = O, j = Number(/* @__PURE__ */ new Date()), F = j - (M || j);
        U.diff = F, U.prev = M, U.curr = j, M = j, N[0] = i.coerce(N[0]), typeof N[0] != "string" && N.unshift("%O");
        let C = 0;
        N[0] = N[0].replace(/%([a-zA-Z%])/g, (V, Z) => {
          if (V === "%%")
            return "%";
          C++;
          const K = i.formatters[Z];
          if (typeof K == "function") {
            const G = N[C];
            V = K.call(U, G), N.splice(C, 1), C--;
          }
          return V;
        }), i.formatArgs.call(U, N), (U.log || i.log).apply(U, N);
      }
      return O.namespace = S, O.useColors = i.useColors(), O.color = i.selectColor(S), O.extend = o, O.destroy = i.destroy, Object.defineProperty(O, "enabled", {
        enumerable: !0,
        configurable: !1,
        get: () => I !== null ? I : (_ !== i.namespaces && (_ = i.namespaces, E = i.enabled(S)), E),
        set: (N) => {
          I = N;
        }
      }), typeof i.init == "function" && i.init(O), O;
    }
    function o(S, M) {
      const I = i(this.namespace + (typeof M > "u" ? ":" : M) + S);
      return I.log = this.log, I;
    }
    function a(S) {
      i.save(S), i.namespaces = S, i.names = [], i.skips = [];
      const M = (typeof S == "string" ? S : "").trim().replace(/\s+/g, ",").split(",").filter(Boolean);
      for (const I of M)
        I[0] === "-" ? i.skips.push(I.slice(1)) : i.names.push(I);
    }
    function p(S, M) {
      let I = 0, _ = 0, E = -1, O = 0;
      for (; I < S.length; )
        if (_ < M.length && (M[_] === S[I] || M[_] === "*"))
          M[_] === "*" ? (E = _, O = I, _++) : (I++, _++);
        else if (E !== -1)
          _ = E + 1, O++, I = O;
        else
          return !1;
      for (; _ < M.length && M[_] === "*"; )
        _++;
      return _ === M.length;
    }
    function c() {
      const S = [
        ...i.names,
        ...i.skips.map((M) => "-" + M)
      ].join(",");
      return i.enable(""), S;
    }
    function g(S) {
      for (const M of i.skips)
        if (p(S, M))
          return !1;
      for (const M of i.names)
        if (p(S, M))
          return !0;
      return !1;
    }
    function h(S) {
      return S instanceof Error ? S.stack || S.message : S;
    }
    function m() {
      console.warn("Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`.");
    }
    return i.enable(i.load()), i;
  }
  return Aa = r, Aa;
}
var Go;
function th() {
  return Go || (Go = 1, (function(r, e) {
    var t = {};
    e.formatArgs = o, e.save = a, e.load = p, e.useColors = i, e.storage = c(), e.destroy = /* @__PURE__ */ (() => {
      let h = !1;
      return () => {
        h || (h = !0, console.warn("Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`."));
      };
    })(), e.colors = [
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
    function i() {
      if (typeof window < "u" && window.process && (window.process.type === "renderer" || window.process.__nwjs))
        return !0;
      if (typeof navigator < "u" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/(edge|trident)\/(\d+)/))
        return !1;
      let h;
      return typeof document < "u" && document.documentElement && document.documentElement.style && document.documentElement.style.WebkitAppearance || // Is firebug? http://stackoverflow.com/a/398120/376773
      typeof window < "u" && window.console && (window.console.firebug || window.console.exception && window.console.table) || // Is firefox >= v31?
      // https://developer.mozilla.org/en-US/docs/Tools/Web_Console#Styling_messages
      typeof navigator < "u" && navigator.userAgent && (h = navigator.userAgent.toLowerCase().match(/firefox\/(\d+)/)) && parseInt(h[1], 10) >= 31 || // Double check webkit in userAgent just in case we are in a worker
      typeof navigator < "u" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/applewebkit\/(\d+)/);
    }
    function o(h) {
      if (h[0] = (this.useColors ? "%c" : "") + this.namespace + (this.useColors ? " %c" : " ") + h[0] + (this.useColors ? "%c " : " ") + "+" + r.exports.humanize(this.diff), !this.useColors)
        return;
      const m = "color: " + this.color;
      h.splice(1, 0, m, "color: inherit");
      let S = 0, M = 0;
      h[0].replace(/%[a-zA-Z%]/g, (I) => {
        I !== "%%" && (S++, I === "%c" && (M = S));
      }), h.splice(M, 0, m);
    }
    e.log = console.debug || console.log || (() => {
    });
    function a(h) {
      try {
        h ? e.storage.setItem("debug", h) : e.storage.removeItem("debug");
      } catch {
      }
    }
    function p() {
      let h;
      try {
        h = e.storage.getItem("debug") || e.storage.getItem("DEBUG");
      } catch {
      }
      return !h && typeof process < "u" && "env" in process && (h = t.DEBUG), h;
    }
    function c() {
      try {
        return localStorage;
      } catch {
      }
    }
    r.exports = eh()(e);
    const { formatters: g } = r.exports;
    g.j = function(h) {
      try {
        return JSON.stringify(h);
      } catch (m) {
        return "[UnexpectedJSONParseError]: " + m.message;
      }
    };
  })(wi, wi.exports)), wi.exports;
}
var Gr = th(), xi = { exports: {} }, Wo;
function rh() {
  if (Wo) return xi.exports;
  Wo = 1;
  var r = typeof Reflect == "object" ? Reflect : null, e = r && typeof r.apply == "function" ? r.apply : function(C, q, V) {
    return Function.prototype.apply.call(C, q, V);
  }, t;
  r && typeof r.ownKeys == "function" ? t = r.ownKeys : Object.getOwnPropertySymbols ? t = function(C) {
    return Object.getOwnPropertyNames(C).concat(Object.getOwnPropertySymbols(C));
  } : t = function(C) {
    return Object.getOwnPropertyNames(C);
  };
  function i(F) {
    console && console.warn && console.warn(F);
  }
  var o = Number.isNaN || function(C) {
    return C !== C;
  };
  function a() {
    a.init.call(this);
  }
  xi.exports = a, xi.exports.once = N, a.EventEmitter = a, a.prototype._events = void 0, a.prototype._eventsCount = 0, a.prototype._maxListeners = void 0;
  var p = 10;
  function c(F) {
    if (typeof F != "function")
      throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof F);
  }
  Object.defineProperty(a, "defaultMaxListeners", {
    enumerable: !0,
    get: function() {
      return p;
    },
    set: function(F) {
      if (typeof F != "number" || F < 0 || o(F))
        throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + F + ".");
      p = F;
    }
  }), a.init = function() {
    (this._events === void 0 || this._events === Object.getPrototypeOf(this)._events) && (this._events = /* @__PURE__ */ Object.create(null), this._eventsCount = 0), this._maxListeners = this._maxListeners || void 0;
  }, a.prototype.setMaxListeners = function(C) {
    if (typeof C != "number" || C < 0 || o(C))
      throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + C + ".");
    return this._maxListeners = C, this;
  };
  function g(F) {
    return F._maxListeners === void 0 ? a.defaultMaxListeners : F._maxListeners;
  }
  a.prototype.getMaxListeners = function() {
    return g(this);
  }, a.prototype.emit = function(C) {
    for (var q = [], V = 1; V < arguments.length; V++) q.push(arguments[V]);
    var Z = C === "error", K = this._events;
    if (K !== void 0)
      Z = Z && K.error === void 0;
    else if (!Z)
      return !1;
    if (Z) {
      var G;
      if (q.length > 0 && (G = q[0]), G instanceof Error)
        throw G;
      var z = new Error("Unhandled error." + (G ? " (" + G.message + ")" : ""));
      throw z.context = G, z;
    }
    var f = K[C];
    if (f === void 0)
      return !1;
    if (typeof f == "function")
      e(f, this, q);
    else
      for (var u = f.length, n = _(f, u), V = 0; V < u; ++V)
        e(n[V], this, q);
    return !0;
  };
  function h(F, C, q, V) {
    var Z, K, G;
    if (c(q), K = F._events, K === void 0 ? (K = F._events = /* @__PURE__ */ Object.create(null), F._eventsCount = 0) : (K.newListener !== void 0 && (F.emit(
      "newListener",
      C,
      q.listener ? q.listener : q
    ), K = F._events), G = K[C]), G === void 0)
      G = K[C] = q, ++F._eventsCount;
    else if (typeof G == "function" ? G = K[C] = V ? [q, G] : [G, q] : V ? G.unshift(q) : G.push(q), Z = g(F), Z > 0 && G.length > Z && !G.warned) {
      G.warned = !0;
      var z = new Error("Possible EventEmitter memory leak detected. " + G.length + " " + String(C) + " listeners added. Use emitter.setMaxListeners() to increase limit");
      z.name = "MaxListenersExceededWarning", z.emitter = F, z.type = C, z.count = G.length, i(z);
    }
    return F;
  }
  a.prototype.addListener = function(C, q) {
    return h(this, C, q, !1);
  }, a.prototype.on = a.prototype.addListener, a.prototype.prependListener = function(C, q) {
    return h(this, C, q, !0);
  };
  function m() {
    if (!this.fired)
      return this.target.removeListener(this.type, this.wrapFn), this.fired = !0, arguments.length === 0 ? this.listener.call(this.target) : this.listener.apply(this.target, arguments);
  }
  function S(F, C, q) {
    var V = { fired: !1, wrapFn: void 0, target: F, type: C, listener: q }, Z = m.bind(V);
    return Z.listener = q, V.wrapFn = Z, Z;
  }
  a.prototype.once = function(C, q) {
    return c(q), this.on(C, S(this, C, q)), this;
  }, a.prototype.prependOnceListener = function(C, q) {
    return c(q), this.prependListener(C, S(this, C, q)), this;
  }, a.prototype.removeListener = function(C, q) {
    var V, Z, K, G, z;
    if (c(q), Z = this._events, Z === void 0)
      return this;
    if (V = Z[C], V === void 0)
      return this;
    if (V === q || V.listener === q)
      --this._eventsCount === 0 ? this._events = /* @__PURE__ */ Object.create(null) : (delete Z[C], Z.removeListener && this.emit("removeListener", C, V.listener || q));
    else if (typeof V != "function") {
      for (K = -1, G = V.length - 1; G >= 0; G--)
        if (V[G] === q || V[G].listener === q) {
          z = V[G].listener, K = G;
          break;
        }
      if (K < 0)
        return this;
      K === 0 ? V.shift() : E(V, K), V.length === 1 && (Z[C] = V[0]), Z.removeListener !== void 0 && this.emit("removeListener", C, z || q);
    }
    return this;
  }, a.prototype.off = a.prototype.removeListener, a.prototype.removeAllListeners = function(C) {
    var q, V, Z;
    if (V = this._events, V === void 0)
      return this;
    if (V.removeListener === void 0)
      return arguments.length === 0 ? (this._events = /* @__PURE__ */ Object.create(null), this._eventsCount = 0) : V[C] !== void 0 && (--this._eventsCount === 0 ? this._events = /* @__PURE__ */ Object.create(null) : delete V[C]), this;
    if (arguments.length === 0) {
      var K = Object.keys(V), G;
      for (Z = 0; Z < K.length; ++Z)
        G = K[Z], G !== "removeListener" && this.removeAllListeners(G);
      return this.removeAllListeners("removeListener"), this._events = /* @__PURE__ */ Object.create(null), this._eventsCount = 0, this;
    }
    if (q = V[C], typeof q == "function")
      this.removeListener(C, q);
    else if (q !== void 0)
      for (Z = q.length - 1; Z >= 0; Z--)
        this.removeListener(C, q[Z]);
    return this;
  };
  function M(F, C, q) {
    var V = F._events;
    if (V === void 0)
      return [];
    var Z = V[C];
    return Z === void 0 ? [] : typeof Z == "function" ? q ? [Z.listener || Z] : [Z] : q ? O(Z) : _(Z, Z.length);
  }
  a.prototype.listeners = function(C) {
    return M(this, C, !0);
  }, a.prototype.rawListeners = function(C) {
    return M(this, C, !1);
  }, a.listenerCount = function(F, C) {
    return typeof F.listenerCount == "function" ? F.listenerCount(C) : I.call(F, C);
  }, a.prototype.listenerCount = I;
  function I(F) {
    var C = this._events;
    if (C !== void 0) {
      var q = C[F];
      if (typeof q == "function")
        return 1;
      if (q !== void 0)
        return q.length;
    }
    return 0;
  }
  a.prototype.eventNames = function() {
    return this._eventsCount > 0 ? t(this._events) : [];
  };
  function _(F, C) {
    for (var q = new Array(C), V = 0; V < C; ++V)
      q[V] = F[V];
    return q;
  }
  function E(F, C) {
    for (; C + 1 < F.length; C++)
      F[C] = F[C + 1];
    F.pop();
  }
  function O(F) {
    for (var C = new Array(F.length), q = 0; q < C.length; ++q)
      C[q] = F[q].listener || F[q];
    return C;
  }
  function N(F, C) {
    return new Promise(function(q, V) {
      function Z(G) {
        F.removeListener(C, K), V(G);
      }
      function K() {
        typeof F.removeListener == "function" && F.removeListener("error", Z), q([].slice.call(arguments));
      }
      j(F, C, K, { once: !0 }), C !== "error" && U(F, Z, { once: !0 });
    });
  }
  function U(F, C, q) {
    typeof F.on == "function" && j(F, "error", C, q);
  }
  function j(F, C, q, V) {
    if (typeof F.on == "function")
      V.once ? F.once(C, q) : F.on(C, q);
    else if (typeof F.addEventListener == "function")
      F.addEventListener(C, function Z(K) {
        V.once && F.removeEventListener(C, Z), q(K);
      });
    else
      throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type ' + typeof F);
  }
  return xi.exports;
}
var vn = rh(), _a, Jo;
function ih() {
  if (Jo) return _a;
  Jo = 1;
  var r = null;
  return typeof WebSocket < "u" ? r = WebSocket : typeof MozWebSocket < "u" ? r = MozWebSocket : typeof globalThis < "u" ? r = globalThis.WebSocket || globalThis.MozWebSocket : typeof window < "u" ? r = window.WebSocket || window.MozWebSocket : typeof self < "u" && (r = self.WebSocket || self.MozWebSocket), _a = r, _a;
}
var ah = ih();
const Yo = /* @__PURE__ */ Fi(ah);
function qi(r) {
  return nh.test(r);
}
var nh = /^-?[0-9]+$/;
function oh(r) {
  return sh.test(r);
}
var sh = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;
function Zs(r, e) {
  var t = parseFloat(r), i = String(t), o = Xo(r), a = Xo(i);
  if (o === a)
    return !0;
  if (e?.approx === !0) {
    var p = 14;
    if (!qi(r) && a.length >= p && o.startsWith(a.substring(0, p)))
      return !0;
  }
  return !1;
}
var ii = /* @__PURE__ */ (function(r) {
  return r.underflow = "underflow", r.overflow = "overflow", r.truncate_integer = "truncate_integer", r.truncate_float = "truncate_float", r;
})({});
function uh(r) {
  if (!Zs(r, {
    approx: !1
  })) {
    if (qi(r))
      return ii.truncate_integer;
    var e = parseFloat(r);
    return isFinite(e) ? e === 0 ? ii.underflow : ii.truncate_float : ii.overflow;
  }
}
function Xo(r) {
  return r.replace(fh, "").replace(lh, "").replace(hh, "").replace(ch, "");
}
var fh = /[eE][+-]?\d+$/, ch = /^-?(0*)?/, lh = /\./, hh = /0+$/;
function Qr(r) {
  "@babel/helpers - typeof";
  return Qr = typeof Symbol == "function" && typeof Symbol.iterator == "symbol" ? function(e) {
    return typeof e;
  } : function(e) {
    return e && typeof Symbol == "function" && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e;
  }, Qr(r);
}
function dh(r, e) {
  if (!(r instanceof e))
    throw new TypeError("Cannot call a class as a function");
}
function ph(r, e) {
  for (var t = 0; t < e.length; t++) {
    var i = e[t];
    i.enumerable = i.enumerable || !1, i.configurable = !0, "value" in i && (i.writable = !0), Object.defineProperty(r, Qs(i.key), i);
  }
}
function mh(r, e, t) {
  return e && ph(r.prototype, e), Object.defineProperty(r, "prototype", { writable: !1 }), r;
}
function bh(r, e, t) {
  return e = Qs(e), e in r ? Object.defineProperty(r, e, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : r[e] = t, r;
}
function Qs(r) {
  var e = vh(r, "string");
  return Qr(e) === "symbol" ? e : String(e);
}
function vh(r, e) {
  if (Qr(r) !== "object" || r === null) return r;
  var t = r[Symbol.toPrimitive];
  if (t !== void 0) {
    var i = t.call(r, e);
    if (Qr(i) !== "object") return i;
    throw new TypeError("@@toPrimitive must return a primitive value.");
  }
  return (e === "string" ? String : Number)(r);
}
var gh = /* @__PURE__ */ (function() {
  function r(e) {
    if (dh(this, r), bh(this, "isLosslessNumber", !0), !oh(e))
      throw new Error('Invalid number (value: "' + e + '")');
    this.value = e;
  }
  return mh(r, [{
    key: "valueOf",
    value: function() {
      var t = uh(this.value);
      if (t === void 0 || t === ii.truncate_float)
        return parseFloat(this.value);
      if (qi(this.value))
        return BigInt(this.value);
      throw new Error("Cannot safely convert to number: " + "the value '".concat(this.value, "' would ").concat(t, " and become ").concat(parseFloat(this.value)));
    }
    /**
     * Get the value of the LosslessNumber as string.
     */
  }, {
    key: "toString",
    value: function() {
      return this.value;
    }
    // Note: we do NOT implement a .toJSON() method, and you should not implement
    // or use that, it cannot safely turn the numeric value in the string into
    // stringified JSON since it has to be parsed into a number first.
  }]), r;
})();
function yh(r) {
  return r && Qr(r) === "object" && r.isLosslessNumber === !0 || !1;
}
function wh(r) {
  return new gh(r);
}
function Ha(r) {
  "@babel/helpers - typeof";
  return Ha = typeof Symbol == "function" && typeof Symbol.iterator == "symbol" ? function(e) {
    return typeof e;
  } : function(e) {
    return e && typeof Symbol == "function" && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e;
  }, Ha(r);
}
function xh(r, e) {
  return gn({
    "": r
  }, "", r, e);
}
function gn(r, e, t, i) {
  return Array.isArray(t) ? i.call(r, e, Sh(t, i)) : t && Ha(t) === "object" && !yh(t) ? i.call(r, e, kh(t, i)) : i.call(r, e, t);
}
function kh(r, e) {
  return Object.keys(r).forEach(function(t) {
    var i = gn(r, t, r[t], e);
    i !== void 0 ? r[t] = i : delete r[t];
  }), r;
}
function Sh(r, e) {
  for (var t = 0; t < r.length; t++)
    r[t] = gn(r, t + "", r[t], e);
  return r;
}
function Va(r) {
  "@babel/helpers - typeof";
  return Va = typeof Symbol == "function" && typeof Symbol.iterator == "symbol" ? function(e) {
    return typeof e;
  } : function(e) {
    return e && typeof Symbol == "function" && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e;
  }, Va(r);
}
function Ma(r) {
  return Bh(r) || Mh(r) || _h(r) || Ah();
}
function Ah() {
  throw new TypeError(`Invalid attempt to spread non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`);
}
function _h(r, e) {
  if (r) {
    if (typeof r == "string") return Ga(r, e);
    var t = Object.prototype.toString.call(r).slice(8, -1);
    if (t === "Object" && r.constructor && (t = r.constructor.name), t === "Map" || t === "Set") return Array.from(r);
    if (t === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t)) return Ga(r, e);
  }
}
function Mh(r) {
  if (typeof Symbol < "u" && r[Symbol.iterator] != null || r["@@iterator"] != null) return Array.from(r);
}
function Bh(r) {
  if (Array.isArray(r)) return Ga(r);
}
function Ga(r, e) {
  (e == null || e > r.length) && (e = r.length);
  for (var t = 0, i = new Array(e); t < e; t++) i[t] = r[t];
  return i;
}
function Ih(r, e) {
  var t = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : wh, i = 0, o = c();
  return _(o), O(), e ? xh(o, e) : o;
  function a() {
    if (r.charCodeAt(i) === Nh) {
      i++, h();
      for (var n = {}, s = !0; i < r.length && r.charCodeAt(i) !== Qo; ) {
        s ? s = !1 : (M(), h());
        var d = i, w = m();
        w === void 0 && j(), h(), I();
        var A = c();
        A === void 0 && K(), Object.prototype.hasOwnProperty.call(n, w) && !Wa(A, n[w]) && F(w, d + 1), n[w] = A;
      }
      return r.charCodeAt(i) !== Qo && C(), i++, n;
    }
  }
  function p() {
    if (r.charCodeAt(i) === Ch) {
      i++, h();
      for (var n = [], s = !0; i < r.length && r.charCodeAt(i) !== $o; ) {
        s ? s = !1 : M();
        var d = c();
        E(d), n.push(d);
      }
      return r.charCodeAt(i) !== $o && q(), i++, n;
    }
  }
  function c() {
    var n, s, d, w, A, k;
    h();
    var l = (n = (s = (d = (w = (A = (k = m()) !== null && k !== void 0 ? k : S()) !== null && A !== void 0 ? A : a()) !== null && w !== void 0 ? w : p()) !== null && d !== void 0 ? d : g("true", !0)) !== null && s !== void 0 ? s : g("false", !1)) !== null && n !== void 0 ? n : g("null", null);
    return h(), l;
  }
  function g(n, s) {
    if (r.slice(i, i + n.length) === n)
      return i += n.length, s;
  }
  function h() {
    for (; Eh(r.charCodeAt(i)); )
      i++;
  }
  function m() {
    if (r.charCodeAt(i) === Ba) {
      i++;
      for (var n = ""; i < r.length && r.charCodeAt(i) !== Ba; ) {
        if (r.charCodeAt(i) === Oh) {
          var s = r[i + 1], d = zh[s];
          d !== void 0 ? (n += d, i++) : s === "u" ? ki(r.charCodeAt(i + 2)) && ki(r.charCodeAt(i + 3)) && ki(r.charCodeAt(i + 4)) && ki(r.charCodeAt(i + 5)) ? (n += String.fromCharCode(parseInt(r.slice(i + 2, i + 6), 16)), i += 5) : G(i) : Z(i);
        } else
          Th(r.charCodeAt(i)) ? n += r[i] : V(r[i]);
        i++;
      }
      return U(), i++, n;
    }
  }
  function S() {
    var n = i;
    if (r.charCodeAt(i) === es && (i++, N(n)), r.charCodeAt(i) === yn)
      i++;
    else if (Ph(r.charCodeAt(i)))
      for (i++; Si(r.charCodeAt(i)); )
        i++;
    if (r.charCodeAt(i) === Dh)
      for (i++, N(n); Si(r.charCodeAt(i)); )
        i++;
    if (r.charCodeAt(i) === Jh || r.charCodeAt(i) === Wh)
      for (i++, (r.charCodeAt(i) === es || r.charCodeAt(i) === jh) && i++, N(n); Si(r.charCodeAt(i)); )
        i++;
    if (i > n)
      return t(r.slice(n, i));
  }
  function M() {
    if (r.charCodeAt(i) !== qh)
      throw new SyntaxError("Comma ',' expected after value ".concat(u()));
    i++;
  }
  function I() {
    if (r.charCodeAt(i) !== Hh)
      throw new SyntaxError("Colon ':' expected after property name ".concat(u()));
    i++;
  }
  function _(n) {
    if (n === void 0)
      throw new SyntaxError("JSON value expected ".concat(u()));
  }
  function E(n) {
    if (n === void 0)
      throw new SyntaxError("Array item expected ".concat(u()));
  }
  function O() {
    if (i < r.length)
      throw new SyntaxError("Expected end of input ".concat(u()));
  }
  function N(n) {
    if (!Si(r.charCodeAt(i))) {
      var s = r.slice(n, i);
      throw new SyntaxError("Invalid number '".concat(s, "', expecting a digit ").concat(u()));
    }
  }
  function U() {
    if (r.charCodeAt(i) !== Ba)
      throw new SyntaxError(`End of string '"' expected `.concat(u()));
  }
  function j() {
    throw new SyntaxError("Quoted object key expected ".concat(u()));
  }
  function F(n, s) {
    throw new SyntaxError("Duplicate key '".concat(n, "' encountered at position ").concat(s));
  }
  function C() {
    throw new SyntaxError("Quoted object key or end of object '}' expected ".concat(u()));
  }
  function q() {
    throw new SyntaxError("Array item or end of array ']' expected ".concat(u()));
  }
  function V(n) {
    throw new SyntaxError("Invalid character '".concat(n, "' ").concat(z()));
  }
  function Z(n) {
    var s = r.slice(n, n + 2);
    throw new SyntaxError("Invalid escape character '".concat(s, "' ").concat(z()));
  }
  function K() {
    throw new SyntaxError("Object value expected after ':' ".concat(z()));
  }
  function G(n) {
    for (var s = n + 2; /\w/.test(r[s]); )
      s++;
    var d = r.slice(n, s);
    throw new SyntaxError("Invalid unicode character '".concat(d, "' ").concat(z()));
  }
  function z() {
    return "at position ".concat(i);
  }
  function f() {
    return i < r.length ? "but got '".concat(r[i], "'") : "but reached end of input";
  }
  function u() {
    return f() + " " + z();
  }
}
function Eh(r) {
  return r === Fh || r === Rh || r === Lh || r === Uh;
}
function ki(r) {
  return r >= yn && r <= wn || r >= Vh && r <= Yh || r >= Gh && r <= Xh;
}
function Si(r) {
  return r >= yn && r <= wn;
}
function Ph(r) {
  return r >= Kh && r <= wn;
}
function Th(r) {
  return r >= 32 && r <= 1114111;
}
function Wa(r, e) {
  if (r === e)
    return !0;
  if (Array.isArray(r) && Array.isArray(e))
    return r.length === e.length && r.every(function(i, o) {
      return Wa(i, e[o]);
    });
  if (Zo(r) && Zo(e)) {
    var t = Ma(new Set([].concat(Ma(Object.keys(r)), Ma(Object.keys(e)))));
    return t.every(function(i) {
      return Wa(r[i], e[i]);
    });
  }
  return !1;
}
function Zo(r) {
  return Va(r) === "object" && r !== null;
}
var zh = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: `
`,
  r: "\r",
  t: "	"
  // note that \u is handled separately in parseString()
}, Oh = 92, Nh = 123, Qo = 125, Ch = 91, $o = 93, Fh = 32, Rh = 10, Lh = 9, Uh = 13, Ba = 34, jh = 43, es = 45, yn = 48, Kh = 49, wn = 57, qh = 44, Dh = 46, Hh = 58, Vh = 65, Gh = 97, Wh = 69, Jh = 101, Yh = 70, Xh = 102;
const We = {
  client: Gr.debug("electrum-cash:client "),
  cluster: Gr.debug("electrum-cash:cluster"),
  errors: Gr.debug("electrum-cash:error  "),
  warning: Gr.debug("electrum-cash:warning"),
  network: Gr.debug("electrum-cash:network"),
  ping: Gr.debug("electrum-cash:pulses ")
};
We.client.color = "2";
We.cluster.color = "3";
We.errors.color = "9";
We.warning.color = "13";
We.network.color = "4";
We.ping.color = "8";
class Rr {
  /**
   * Helper function that builds an Electrum request object.
   *
   * @param {string} method       method to call.
   * @param {array}  parameters   method parameters for the call.
   * @param {string} requestId    unique string or number referencing this request.
   *
   * @returns a properly formatted Electrum request string.
   */
  static buildRequestObject(e, t, i) {
    return JSON.stringify({ method: e, params: t, id: i });
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
    return `
`;
  }
}
const Zh = function(r) {
  return "error" in r;
};
var Ja;
(function(r) {
  r[r.RANDOM = 0] = "RANDOM", r[r.PRIORITY = 1] = "PRIORITY";
})(Ja || (Ja = {}));
var Ya;
(function(r) {
  r[r.ALL = 0] = "ALL";
})(Ya || (Ya = {}));
var ts;
(function(r) {
  r[r.DISABLED = 0] = "DISABLED", r[r.DEGRADED = 1] = "DEGRADED", r[r.READY = 2] = "READY";
})(ts || (ts = {}));
var rs;
(function(r) {
  r[r.UNAVAILABLE = 0] = "UNAVAILABLE", r[r.AVAILABLE = 1] = "AVAILABLE";
})(rs || (rs = {}));
var bt;
(function(r) {
  r[r.DISCONNECTED = 0] = "DISCONNECTED", r[r.CONNECTED = 1] = "CONNECTED", r[r.DISCONNECTING = 2] = "DISCONNECTING", r[r.CONNECTING = 3] = "CONNECTING", r[r.RECONNECTING = 4] = "RECONNECTING";
})(bt || (bt = {}));
const jt = {
  TCP: { Scheme: "tcp" },
  TCP_TLS: { Port: 50002, Scheme: "tcp_tls" },
  WS: { Scheme: "ws" },
  WSS: { Scheme: "wss" }
}, qt = {
  // Port number for TCP TLS connections
  PORT: jt.TCP_TLS.Port,
  // Transport to connect to the Electrum server
  TRANSPORT_SCHEME: jt.TCP_TLS.Scheme,
  // How long to wait before attempting to reconnect, in milliseconds.
  RECONNECT: 15 * 1e3,
  // How long to wait for network operations before following up, in milliseconds.
  TIMEOUT: 120 * 1e3,
  // Time between ping messages, in milliseconds. Pinging keeps the connection alive.
  // The reason for pinging this frequently is to detect connection problems early.
  PING_INTERVAL: 3 * 1e3,
  // How many servers we send requests to.
  CLUSTER_DISTRIBUTION: Ya.ALL,
  // What order we select servers to send requests to.
  CLUSTER_ORDER: Ja.RANDOM,
  // If we use lossless json lib to parse json response.
  LOSSLESS_JSON_PARSER: !1
};
class Qh extends vn.EventEmitter {
  // Declare an empty TCP socket.
  tcpSocket;
  // Declare an empty WebSocket.
  webSocket;
  // Declare timers for keep-alive pings and reconnection
  timers = {};
  // Initialize boolean that indicates whether the onConnect function has run (initialize to false).
  onConnectHasRun = !1;
  // Initialize event forwarding functions.
  eventForwarders = {
    disconnect: () => this.emit("disconnect"),
    tcpData: (e) => this.emit("data", e),
    wsData: (e) => this.emit("data", `${e.data}
`),
    tcpError: (e) => this.emit("error", e),
    wsError: (e) => this.emit("error", e.error)
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
  connect(e, t, i, o) {
    if (this.tcpSocket || this.webSocket)
      throw new Error("Cannot initiate a new socket connection when an existing connection exists");
    this.timers.disconnect = setTimeout(() => this.disconnectOnTimeout(e, t, o), o), this.once("connect", this.clearDisconnectTimerOnTimeout);
    const a = {
      [jt.TCP.Scheme]: "a TCP Socket",
      [jt.TCP_TLS.Scheme]: "an encrypted TCP socket",
      [jt.WS.Scheme]: "a WebSocket",
      [jt.WSS.Scheme]: "an encrypted WebSocket"
    };
    if (We.network(`Initiating ${a[i]} connection to '${e}:${t}'.`), i === jt.TCP.Scheme || i === jt.TCP_TLS.Scheme) {
      if (i === jt.TCP_TLS.Scheme) {
        const p = { rejectUnauthorized: !1 };
        Yt.isIP(e) || (p.serverName = e), this.tcpSocket = Yt.connect(t, e, p), this.tcpSocket.once("secureConnect", () => {
          if (!(this.tcpSocket instanceof Yt.TLSSocket))
            return;
          this.tcpSocket.authorizationError === "DEPTH_ZERO_SELF_SIGNED_CERT" && We.warning(`Connection to ${e}:${t} uses a self-signed certificate`);
        }), this.tcpSocket.on("secureConnect", this.onConnect.bind(this, a[i], e, t));
      } else
        this.tcpSocket = Yt.connect({ host: e, port: t }), this.tcpSocket.on("connect", this.onConnect.bind(this, a[i], e, t));
      this.tcpSocket.setEncoding("utf8"), this.tcpSocket.setKeepAlive(!0, 0), this.tcpSocket.setNoDelay(!0), this.tcpSocket.on("error", this.eventForwarders.tcpError);
    } else if (i === jt.WS.Scheme || i === jt.WSS.Scheme)
      i === jt.WSS.Scheme ? this.webSocket = new Yo(`wss://${e}:${t}`) : this.webSocket = new Yo(`ws://${e}:${t}`), this.webSocket.addEventListener("open", this.onConnect.bind(this, a[i], e, t)), this.webSocket.addEventListener("error", this.eventForwarders.wsError);
    else
      throw new Error("Incorrect transport specified");
  }
  /**
   * Sets up forwarding of events related to the connection.
   *
   * @param {string} connectionType   Name of the connection/transport type, used for logging.
   * @param {string} host             Fully qualified domain name or IP address of the host
   * @param {number} port             Network port for the host to connect to
   */
  onConnect(e, t, i) {
    this.onConnectHasRun || (We.network(`Established ${e} connection with '${t}:${i}'.`), typeof this.tcpSocket < "u" ? (this.tcpSocket.addListener("close", this.eventForwarders.disconnect), this.tcpSocket.addListener("data", this.eventForwarders.tcpData)) : typeof this.webSocket < "u" && (this.webSocket.addEventListener("close", this.eventForwarders.disconnect), this.webSocket.addEventListener("message", this.eventForwarders.wsData)), this.onConnectHasRun = !0, this.emit("connect"));
  }
  /**
   * Clears the disconnect timer if it is still active.
   */
  clearDisconnectTimerOnTimeout() {
    this.timers.disconnect && clearTimeout(this.timers.disconnect);
  }
  /**
   * Forcibly terminate the connection.
   *
   * @throws {Error} if no connection was found
   */
  disconnect() {
    if (this.clearDisconnectTimerOnTimeout(), this.tcpSocket)
      this.tcpSocket.removeListener("close", this.eventForwarders.disconnect), this.tcpSocket.removeListener("data", this.eventForwarders.tcpData), this.tcpSocket.removeListener("error", this.eventForwarders.tcpError), this.tcpSocket.destroy(), this.tcpSocket = void 0;
    else if (this.webSocket)
      try {
        this.webSocket.removeEventListener("close", this.eventForwarders.disconnect), this.webSocket.removeEventListener("message", this.eventForwarders.wsData), this.webSocket.removeEventListener("error", this.eventForwarders.wsError), this.webSocket.close();
      } catch {
      } finally {
        this.webSocket = void 0;
      }
    this.onConnectHasRun = !1, this.emit("disconnect");
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
  write(e, t) {
    if (this.tcpSocket)
      return this.tcpSocket.write(e, t);
    if (this.webSocket)
      return this.webSocket.send(e, t), !0;
    throw new Error("Cannot write to socket when there is no active connection");
  }
  /**
   * Force a disconnection if no connection is established after `timeout` milliseconds.
   *
   * @param {string} host      Host of the connection that timed out
   * @param {number} port      Port of the connection that timed out
   * @param {number} timeout   Elapsed milliseconds
   */
  disconnectOnTimeout(e, t, i) {
    this.removeListener("connect", this.clearDisconnectTimerOnTimeout);
    const o = { code: "ETIMEDOUT", message: `Connection to '${e}:${t}' timed out after ${i} milliseconds` };
    this.emit("error", o), this.disconnect();
  }
}
class $h extends vn.EventEmitter {
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
  status = bt.DISCONNECTED;
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
  constructor(e, t, i, o = qt.PORT, a = qt.TRANSPORT_SCHEME, p = qt.TIMEOUT, c = qt.PING_INTERVAL, g = qt.LOSSLESS_JSON_PARSER) {
    if (super(), this.application = e, this.version = t, this.host = i, this.port = o, this.scheme = a, this.timeout = p, this.pingInterval = c, this.useLosslessJsonParser = g, !Rr.versionRegexp.test(t))
      throw new Error(`Provided version string (${t}) is not a valid protocol version number.`);
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
    this.socket = new Qh(), this.socket.on("connect", this.onSocketConnect.bind(this)), this.socket.on("disconnect", this.onSocketDisconnect.bind(this)), this.socket.on("data", this.parseMessageChunk.bind(this));
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
  parseMessageChunk(e) {
    for (this.lastReceivedTimestamp = Date.now(), this.verifications.forEach((t) => clearTimeout(t)), this.verifications.length = 0, this.messageBuffer += e; this.messageBuffer.includes(Rr.statementDelimiter); ) {
      const t = this.messageBuffer.split(Rr.statementDelimiter);
      for (; t.length > 1; ) {
        const i = String(t.shift());
        let o;
        for (this.useLosslessJsonParser ? o = Ih(i, void 0, (a) => qi(a) && (!Zs(a) || parseInt(a) > Number.MAX_SAFE_INTEGER) ? BigInt(a) : parseFloat(a)) : o = JSON.parse(i), Array.isArray(o) || (o = [o]); o.length > 0; ) {
          const a = o.shift();
          if (a.id === "versionNegotiation") {
            a.error ? this.emit("version", { error: a.error }) : this.emit("version", { software: a.result[0], protocol: a.result[1] });
            continue;
          }
          a.id !== "keepAlive" && this.emit("statement", a);
        }
      }
      this.messageBuffer = t.shift() || "";
    }
  }
  /**
   * Sends a keep-alive message to the host.
   *
   * @returns true if the ping message was fully flushed to the socket, false if
   * part of the message is queued in the user memory
   */
  ping() {
    We.ping(`Sending keep-alive ping to '${this.hostIdentifier}'`);
    const e = Rr.buildRequestObject("server.ping", [], "keepAlive");
    return this.send(e);
  }
  /**
   * Initiates the network connection negotiates a protocol version. Also emits the 'connect' signal if successful.
   *
   * @throws {Error} if the socket connection fails.
   * @returns a promise resolving when the connection is established
   */
  async connect() {
    if (this.status === bt.CONNECTED)
      return;
    this.status = bt.CONNECTING;
    const e = (t, i) => {
      const o = (p) => {
        this.status = bt.DISCONNECTED, i(p);
      };
      this.socket.removeAllListeners("error"), this.socket.once("error", o);
      const a = () => {
        We.network(`Requesting protocol version ${this.version} with '${this.hostIdentifier}'.`), this.socket.removeListener("error", o);
        const p = Rr.buildRequestObject("server.version", [this.application, this.version], "versionNegotiation"), c = (g) => {
          if (Zh(g)) {
            this.disconnect(!0);
            const h = "unsupported protocol version.";
            We.errors(`Failed to connect with ${this.hostIdentifier} due to ${h}`), i(h);
          } else if (g.protocol !== this.version) {
            this.disconnect(!0);
            const h = `incompatible protocol version negotiated (${g.protocol} !== ${this.version}).`;
            We.errors(`Failed to connect with ${this.hostIdentifier} due to ${h}`), i(h);
          } else
            We.network(`Negotiated protocol version ${g.protocol} with '${this.hostIdentifier}', powered by ${g.software}.`), this.status = bt.CONNECTED, this.emit("connect"), t();
        };
        this.once("version", c), this.send(p);
      };
      this.socket.once("connect", a), this.socket.on("error", this.onSocketError.bind(this)), this.socket.connect(this.host, this.port, this.scheme, this.timeout);
    };
    await new Promise(e);
  }
  /**
   * Restores the network connection.
   */
  async reconnect() {
    await this.clearReconnectTimer(), We.network(`Trying to reconnect to '${this.hostIdentifier}'..`), this.status = bt.RECONNECTING, this.destroySocket(), this.createSocket();
    try {
      await this.connect();
    } catch {
    }
  }
  /**
   * Removes the current reconnect timer.
   */
  clearReconnectTimer() {
    this.timers.reconnect && clearTimeout(this.timers.reconnect), this.timers.reconnect = void 0;
  }
  /**
   * Removes the current keep-alive timer.
   */
  clearKeepAliveTimer() {
    this.timers.keepAlive && clearTimeout(this.timers.keepAlive), this.timers.keepAlive = void 0;
  }
  /**
   * Initializes the keep alive timer loop.
   */
  setupKeepAliveTimer() {
    this.timers.keepAlive || (this.timers.keepAlive = setTimeout(this.ping.bind(this), this.pingInterval));
  }
  /**
   * Tears down the current connection and removes all event listeners on disconnect.
   *
   * @param {boolean} force   disconnect even if the connection has not been fully established yet.
   *
   * @returns true if successfully disconnected, or false if there was no connection.
   */
  async disconnect(e = !1) {
    if (this.status === bt.DISCONNECTED && !e)
      return !1;
    this.status = bt.DISCONNECTING, await this.clearKeepAliveTimer(), await this.clearReconnectTimer();
    const t = (i) => {
      this.once("disconnect", () => i(!0)), this.destroySocket();
    };
    return new Promise(t);
  }
  /**
   * Sends an arbitrary message to the server.
   *
   * @param {string} message   json encoded request object to send to the server, as a string.
   *
   * @returns true if the message was fully flushed to the socket, false if part of the message
   * is queued in the user memory
   */
  send(e) {
    this.clearKeepAliveTimer();
    const t = Date.now(), i = setTimeout(this.verifySend.bind(this, t), this.timeout);
    return this.verifications.push(i), this.setupKeepAliveTimer(), this.socket.write(e + Rr.statementDelimiter);
  }
  // --- Event managers. --- //
  /**
   * Marks the connection as timed out and schedules reconnection if we have not
   * received data within the expected time frame.
   */
  verifySend(e) {
    if (Number(this.lastReceivedTimestamp) < e) {
      if (this.status === bt.DISCONNECTED || this.status === bt.DISCONNECTING) {
        We.errors(`Tried to verify already disconnected connection to '${this.hostIdentifier}'`);
        return;
      }
      this.clearKeepAliveTimer(), We.network(`Connection to '${this.hostIdentifier}' timed out.`), this.socket.disconnect();
    }
  }
  /**
   * Updates the connection status when a connection is confirmed.
   */
  onSocketConnect() {
    this.clearReconnectTimer(), this.lastReceivedTimestamp = Date.now(), this.setupKeepAliveTimer(), this.socket.removeAllListeners("error"), this.socket.on("error", this.onSocketError.bind(this));
  }
  /**
   * Updates the connection status when a connection is ended.
   */
  onSocketDisconnect() {
    this.emit("disconnect"), this.clearKeepAliveTimer(), this.status === bt.DISCONNECTING ? (this.clearReconnectTimer(), this.removeAllListeners(), this.status = bt.DISCONNECTED, We.network(`Disconnected from '${this.hostIdentifier}'.`)) : (this.status === bt.CONNECTED && We.errors(`Connection with '${this.hostIdentifier}' was closed, trying to reconnect in ${qt.RECONNECT / 1e3} seconds.`), this.status = bt.DISCONNECTED, this.timers.reconnect || (this.timers.reconnect = setTimeout(this.reconnect.bind(this), qt.RECONNECT)));
  }
  /**
   * Notify administrator of any unexpected errors.
   */
  onSocketError(e) {
    if (!(typeof e > "u")) {
      if (e.code === "EAI_AGAIN") {
        We.errors(`Failed to look up DNS records for '${this.host}'.`);
        return;
      }
      if (e.code === "ETIMEDOUT") {
        We.errors(e.message);
        return;
      }
      We.errors(`Unknown network error ('${this.hostIdentifier}'): `, e);
    }
  }
}
const ed = function(r) {
  return "id" in r && "error" in r;
}, td = function(r) {
  return !("id" in r) && "method" in r;
};
class rd extends vn.EventEmitter {
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
  constructor(e, t, i, o = qt.PORT, a = qt.TRANSPORT_SCHEME, p = qt.TIMEOUT, c = qt.PING_INTERVAL, g = qt.LOSSLESS_JSON_PARSER) {
    super(), this.connection = new $h(e, t, i, o, a, p, c, g);
  }
  /**
   * Connects to the remote server.
   *
   * @throws {Error} if the socket connection fails.
   * @returns a promise resolving when the connection is established.
   */
  async connect() {
    this.connection.on("statement", this.response.bind(this)), this.connection.on("connect", this.resubscribeOnConnect.bind(this)), this.connection.on("connect", this.emit.bind(this, "connected")), this.connection.on("disconnect", this.onConnectionDisconnect.bind(this)), this.connection.on("error", this.emit.bind(this, "error")), await this.connection.connect();
  }
  /**
   * Disconnects from the remote server and removes all event listeners/subscriptions and open requests.
   *
   * @param {boolean} force                 disconnect even if the connection has not been fully established yet.
   * @param {boolean} retainSubscriptions   retain subscription data so they will be restored on reconnection.
   *
   * @returns true if successfully disconnected, or false if there was no connection.
   */
  async disconnect(e = !1, t = !1) {
    t || (this.removeAllListeners(), this.subscriptionMethods = {});
    for (const i in this.requestResolvers) {
      const o = this.requestResolvers[i];
      o(new Error("Manual disconnection")), delete this.requestResolvers[i];
    }
    return this.connection.disconnect(e);
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
  async request(e, ...t) {
    if (this.connection.status !== bt.CONNECTED)
      throw new Error(`Unable to send request to a disconnected server '${this.connection.host}'.`);
    this.requestId += 1;
    const i = this.requestId, o = Rr.buildRequestObject(e, t, i), a = (p) => {
      this.requestResolvers[i] = (c, g) => {
        p(c || g);
      }, this.connection.send(o);
    };
    return We.network(`Sending request '${e}' to '${this.connection.host}'`), new Promise(a);
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
  async subscribe(e, t, ...i) {
    const o = async (a) => {
      this.listeners(t).includes(e) || this.addListener(t, e), this.subscriptionMethods[t] || (this.subscriptionMethods[t] = []), this.subscriptionMethods[t].push(JSON.stringify(i));
      const p = this.subscriptionCallbacks.get(e) || [];
      p.push({ method: t, payload: JSON.stringify(i) }), this.subscriptionCallbacks.set(e, p);
      const c = await this.request(t, ...i);
      e(c), a(!0);
    };
    return new Promise(o);
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
  async unsubscribe(e, t, ...i) {
    if (this.connection.status !== bt.CONNECTED)
      throw new Error(`Unable to send unsubscribe request to a disconnected server '${this.connection.host}'.`);
    const o = async (a) => {
      const p = JSON.stringify(i);
      if (!this.subscriptionMethods[t])
        throw new Error(`Cannot unsubscribe from '${t}' since the method has no subscriptions.`);
      if (!this.subscriptionCallbacks.has(e))
        throw new Error(`Cannot unsubscribe with '${e.name}' since the callback has no subscriptions.`);
      const c = Object.values(this.subscriptionMethods[t]).filter((M) => M === p).length, g = (this.subscriptionCallbacks.get(e) || []).filter((M) => M.method === t).length, h = this.subscriptionMethods[t].indexOf(p), m = (this.subscriptionCallbacks.get(e) || []).findIndex((M) => M.method === t && M.payload === p);
      if (h < 0)
        throw new Error(`Cannot unsubscribe from '${t}' since it has no subscription with the given parameters.`);
      if (m < 0)
        throw new Error(`Cannot unsubscribe with '${e.name}' since it has no subscription with the given method and parameters.`);
      c === 1 && (this.subscriptionMethods[t].splice(h, 1), t.endsWith(".subscribe") && await this.request(t.replace(".subscribe", ".unsubscribe"), ...i)), g === 1 && this.removeListener(t, e);
      const S = this.subscriptionCallbacks.get(e) || [];
      this.subscriptionCallbacks.set(e, S.splice(m, 1)), We.client(`Unsubscribed callback '${e.name}' from '${String(t)}' for the '${p}' parameters.`), a(!0);
    };
    return new Promise(o);
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
    We.client(`Connected to '${this.connection.hostIdentifier}'.`);
    for (const e of this.eventNames())
      if (!(e === "connected" || e === "disconnected" || e === "error")) {
        if (!this.subscriptionMethods[String(e)])
          throw new Error(`Unable to resubscribe to ${String(e)} at ${this.connection.hostIdentifier} due to missing subscription data.`);
        for (const t of this.subscriptionMethods[String(e)]) {
          const i = JSON.parse(t);
          await this.request(String(e), ...i);
        }
        We.client(`Restored ${this.subscriptionMethods[String(e)].length} previous '${String(e)}' subscriptions for '${this.connection.hostIdentifier}'`);
      }
    return !0;
  }
  /**
   * Parser messages from the remote server to resolve request promises and emit subscription events.
   *
   * @param {RPCNotification | RPCResponse} message   the response message
   *
   * @throws {Error} if the message ID does not match an existing request.
   * @ignore
   */
  response(e) {
    if (td(e)) {
      We.client(`Received notification for '${e.method}' from '${this.connection.host}'`), this.emit(e.method, e.params);
      return;
    }
    if (e.id === null)
      throw new Error("Internal error: Received an RPC response with ID null.");
    const t = this.requestResolvers[e.id];
    if (!t)
      throw new Error("Internal error: Callback for response not available.");
    delete this.requestResolvers[e.id], ed(e) ? t(new Error(e.error.message)) : t(void 0, e.result);
  }
  /**
   * Callback function that is called when connection to the Electrum server is lost.
   * Aborts all active requests with an error message indicating that connection was lost.
   *
   * @ignore
   */
  onConnectionDisconnect() {
    this.emit("disconnected");
    for (const e in this.requestResolvers) {
      const t = this.requestResolvers[e];
      t(new Error("Connection lost")), delete this.requestResolvers[e];
    }
  }
}
class Rd {
  static {
    this.encoder = new TextEncoder();
  }
  static {
    this.decoder = new TextDecoder();
  }
  static generateSecret() {
    let e = new Uint8Array(16);
    return crypto.getRandomValues(e), Array.from(e).map((t) => t.toString(16).padStart(2, "0")).join("");
  }
  static async encrypt(e, t) {
    let i = crypto.getRandomValues(new Uint8Array(16)), o = crypto.getRandomValues(new Uint8Array(12)), a = await this.deriveKey(t, i), p = this.encoder.encode(e), c = await crypto.subtle.encrypt({
      name: "AES-GCM",
      iv: o
    }, a, p), g = this.concatBuffers([
      i,
      o,
      new Uint8Array(c)
    ]);
    return this.base64Encode(g);
  }
  static async decrypt(e, t) {
    let i = this.base64Decode(e), o = i.slice(0, 16), a = i.slice(16, 28), p = i.slice(28), c = await this.deriveKey(t, o), g = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: a
    }, c, p);
    return this.decoder.decode(g);
  }
  static async deriveKey(e, t) {
    let i = this.encoder.encode(e), o = await crypto.subtle.importKey("raw", i, "PBKDF2", !1, [
      "deriveKey"
    ]);
    return crypto.subtle.deriveKey({
      name: "PBKDF2",
      salt: t,
      iterations: 1e5,
      hash: "SHA-256"
    }, o, {
      name: "AES-GCM",
      length: 256
    }, !1, [
      "encrypt",
      "decrypt"
    ]);
  }
  static concatBuffers(e) {
    let t = e.reduce((a, p) => a + p.length, 0), i = new Uint8Array(t), o = 0;
    for (let a of e)
      i.set(a, o), o += a.length;
    return i;
  }
  static base64Encode(e) {
    return btoa(String.fromCharCode(...e));
  }
  static base64Decode(e) {
    let t = atob(e), i = t.length, o = new Uint8Array(i);
    for (let a = 0; a < i; a++) o[a] = t.charCodeAt(a);
    return o;
  }
}
var $s = globalThis, xn = {};
xn = JSON.parse('{"name":"nexa-wallet-sdk","version":"0.5.0","type":"module","source":"src/index.ts","types":"dist/index.d.ts","main":"dist/index.cjs","module":"dist/index.mjs","browser":"dist/index.web.mjs","exports":{"types":"./dist/index.d.ts","node":{"import":"./dist/index.mjs","require":"./dist/index.cjs"},"browser":"./dist/index.web.mjs","default":"./dist/index.mjs"},"scripts":{"build":"parcel build","lint":"eslint .","fix-lint":"eslint --fix .","dev":"parcel watch","test":"vitest run","clean":"rm -rf dist .parcel-cache","docs":"typedoc","docs:serve":"typedoc && npx serve docs -l 8080","docs:mkdocs":"typedoc && mkdocs serve","docs:build":"typedoc && mkdocs build","docs:setup":"./scripts/setup-docs.sh","wallet-cli":"node examples/wallet-cli.cjs"},"repository":{"type":"git","url":"git+ssh://git@gitlab.com/nexa/wallet-sdk-ts.git"},"keywords":["nexa","wallet","web3","crypto","dapp","walletcomms","walletsdk"],"contributors":[{"name":"Dolaned"},{"name":"Griffith"},{"name":"Vgrunner"},{"name":"myendy"}],"author":"Dolaned","license":"MIT","bugs":{"url":"https://gitlab.com/nexa/wallet-sdk-ts/issues"},"homepage":"https://gitlab.com/nexa/wallet-sdk-ts#readme","description":"Wallet SDK for the Nexa blockchain","devDependencies":{"@parcel/packager-ts":"^2.15.4","@parcel/transformer-typescript-types":"^2.15.4","@types/lodash-es":"^4.17.12","@types/node":"^22.13.1","eslint":"^9.20.1","parcel":"^2.15.4","typedoc":"^0.28.7","typedoc-plugin-markdown":"^4.7.0","typedoc-plugin-rename-defaults":"^0.7.3","typescript":"^5.8.3","typescript-eslint":"^8.24.1","vitest":"^3.0.8"},"targets":{"main":{"context":"node","outputFormat":"commonjs","distDir":"dist","isLibrary":true,"includeNodeModules":["lodash-es"]},"module":{"context":"node","outputFormat":"esmodule","distDir":"dist","isLibrary":true},"browser":{"context":"browser","outputFormat":"esmodule","distDir":"dist","isLibrary":true}},"dependencies":{"@vgrunner/electrum-cash":"^2.0.12","bip39":"^3.1.0","js-big-decimal":"^2.2.0","libnexa-ts":"^1.0.5","lodash-es":"^4.17.21","prompt-sync":"^4.2.0","wallet-comms-sdk":"^0.6.1"},"files":["dist"],"directories":{"test":"tests"},"@parcel/resolver-default":{"packageExports":true}}');
const Ia = {
  WS: "ws",
  WSS: "wss",
  TCP: "tcp",
  TCP_TLS: "tcp_tls"
};
class id {
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
  async getBalance(e) {
    return await this.execute("blockchain.address.get_balance", e, "exclude_tokens");
  }
  /**
   * Get The transaction history for an address
   * @param address
   */
  async getTransactionHistory(e) {
    return await this.execute("blockchain.address.get_history", e);
  }
  /**
   * Get the block height or block has of when the address was first used
   * @param address
   */
  async getFirstUse(e) {
    return await this.execute("blockchain.address.get_first_use", e);
  }
  /**
   * Get a single transaction object
   * @param id
   * @param verbose
   */
  async getTransaction(e, t = !0) {
    return await this.execute("blockchain.transaction.get", e, t);
  }
  /**
   * Get a single unspent output including group data
   * @param outpoint
   */
  async getUtxo(e) {
    return await this.execute("blockchain.utxo.get", e);
  }
  /**
   * Get Utxos only containing nexa information
   * @param address
   */
  async getNexaUtxos(e) {
    return await this.execute("blockchain.address.listunspent", e, "exclude_tokens");
  }
  /**
   * Get all the utxo's for a token at an address
   * @param address
   * @param token
   */
  async getTokenUtxos(e, t) {
    return (await this.execute("token.address.listunspent", e, null, t)).unspent;
  }
  /**
   * Get the token balances for an address
   * @param address
   * @param token
   */
  async getTokensBalance(e, t) {
    return t ? await this.execute("token.address.get_balance", e, null, t) : await this.execute("token.address.get_balance", e);
  }
  /**
   * Get the token genesis for a token
   * @param token
   */
  async getTokenGenesis(e) {
    return await this.execute("token.genesis.info", e);
  }
  /**
   * Subscribe to address call back notifications, handy for updating the user when they receive nexa or tokens in
   * their wallet
   * @param addresses
   * @param callback
   */
  async subscribeToAddresses(e, t) {
    for (const i of e) await this.client?.subscribe(t, "blockchain.address.subscribe", i);
  }
  /**
   * Unsubscribe from address notifications to prevent memory leaks
   * @param addresses
   * @param callback
   */
  async unsubscribeFromAddresses(e, t) {
    for (const i of e) await this.client?.unsubscribe(t, "blockchain.address.subscribe", i);
  }
  /**
   * Broadcast a presigned transaction hash
   * @param txHex
   */
  async broadcast(e) {
    return await this.execute("blockchain.transaction.broadcast", e);
  }
  /**
   * Get the latency of the server connection
   */
  async getLatency() {
    try {
      let e = Date.now();
      return await this.getBlockTip() ? Date.now() - e : 0;
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
  async connect(e, t, i) {
    try {
      let o;
      if (e && typeof e == "object" && "host" in e && "port" in e && "scheme" in e)
        o = e;
      else if (t)
        o = t;
      else {
        const a = e ? Rt.get(e) : Rt.mainnet;
        a === Rt.mainnet ? o = {
          host: "electrum.nexa.org",
          port: 20004,
          scheme: Ia.WSS
        } : a === Rt.testnet ? o = {
          host: "testnet-electrum.nexa.org",
          port: 30004,
          scheme: Ia.WSS
        } : o = {
          host: "localhost",
          port: 30004,
          scheme: Ia.WS
        };
      }
      i ? (this.client = i, this.client.connection.status == bt.DISCONNECTED && await this.client.connect()) : (this.client = new rd("com.nexa.wallet-sdk", "1.4.3", o.host, o.port, o.scheme, 3e4, 1e4, !0), await this.client.connect());
    } catch (o) {
      throw o instanceof Error ? console.info(o.message) : console.error(o), o;
    }
  }
  /**
   * Disconnect from the rostrum server
   * @param force
   */
  async disconnect(e) {
    try {
      return await this.client.disconnect(e);
    } catch (t) {
      return console.log(t), !1;
    }
  }
  /**
   * internal function to call commands against the rostrum API
   * @param method
   * @param parameters
   * @private
   */
  async execute(e, ...t) {
    let i = await this.client.request(e, ...t);
    if (i instanceof Error) throw i;
    return i;
  }
}
const zt = new id();
class kn {
  get transactions() {
    return this._transactions;
  }
  constructor(e) {
    this._tokenBalances = {}, this._transactions = /* @__PURE__ */ new Map(), this._bip44Account = e, this._balance = {
      confirmed: 0,
      unconfirmed: 0
    }, this._tokenBalances = {};
  }
  get balance() {
    return this._balance;
  }
  set balance(e) {
    this._balance = e;
  }
  get tokenBalances() {
    return this._tokenBalances;
  }
  set tokenBalances(e) {
    this._tokenBalances = e;
  }
  async fetchAndClassifyTransactions(e, t) {
    const i = await Ii([
      e
    ], t ?? 0), o = Array.from(i.txs.values()).map((p) => en(p, [
      e
    ])), a = await Promise.all(o);
    for (let p of a) this.transactions.set(p.txId, p);
    return this.transactions;
  }
}
class eu extends kn {
  constructor(e, t, i) {
    super(e), this._accountIndex = t, this._accountKey = i;
  }
  // this is used in AccountStore.ts to get the key to be used in the map for this account
  getAccountStoreKey() {
    return this._bip44Account + "." + this._accountIndex;
  }
  getAccountType() {
    return Jt.DAPP_ACCOUNT;
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
    let e = await Sn([
      this._accountKey
    ]), t = [
      this._accountKey
    ].map((i) => i.tokensBalance);
    super.balance = An(e), super.tokenBalances = _n(t);
  }
  getKeyFromAddress(e) {
    if (e !== this._accountKey.address) throw new Error(`Address ${e} does not belong to this account`);
    return this._accountKey;
  }
  async getTransactions(e, t) {
    const i = t ?? this._accountKey.address;
    return this.fetchAndClassifyTransactions(i, e);
  }
  getAddresses() {
    return [
      this._accountKey
    ];
  }
  hasChangeAddresses() {
    return !1;
  }
  getPrimaryAddressKey() {
    return this._accountKey;
  }
}
class Xa extends kn {
  constructor(e, t, i) {
    if (super(e), t.rIndex < 0) throw new Error(`Can not create nexa account with an rindex of ${t.rIndex}. must be >= 0.`);
    if (t.cIndex < 0) throw new Error(`Can not create nexa account with an cindex of ${t.cIndex}. must be >= 0.`);
    this._accountIndexes = t, this._accountKeys = i;
  }
  // this is used in AccountStore.ts to get the key to be used in the map for this account
  getAccountStoreKey() {
    return String(this._bip44Account);
  }
  getAccountType() {
    return Jt.NEXA_ACCOUNT;
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
    let e = await Sn(this._accountKeys.receiveKeys.concat(this._accountKeys.changeKeys)), t = this._accountKeys.receiveKeys.concat(this._accountKeys.changeKeys).map((i) => i.tokensBalance);
    super.balance = An(e), super.tokenBalances = _n(t);
  }
  getKeyFromAddress(e) {
    return this._accountKeys.receiveKeys.concat(this._accountKeys.changeKeys).find((o) => o.address === e);
  }
  async getTransactions(e, t) {
    let i = this.accountKeys.receiveKeys.map((I) => I.address), o = this.accountKeys.changeKeys.map((I) => I.address), a = i.concat(o);
    if (t != null) {
      const I = await Ii([
        t
      ], e ?? 0), _ = Array.from(I.txs.values()).map((O) => en(O, a)), E = await Promise.all(_);
      for (let O of E) this.transactions.set(O.txId, O);
      return this.transactions;
    }
    let p = Ii(i, e ?? 0), c = Ii(o, e ?? 0), [g, h] = await Promise.all([
      p,
      c
    ]), m = g.txs;
    for (let I of h.txs.values()) m.set(I.tx_hash, I);
    const S = Array.from(m.values()).map((I) => en(I, a)), M = await Promise.all(S);
    for (let I of M) this.transactions.set(I.txId, I);
    return this.transactions;
  }
  getAddresses() {
    return this._accountKeys.receiveKeys.concat(this._accountKeys.changeKeys);
  }
  hasChangeAddresses() {
    return !0;
  }
  getPrimaryAddressKey() {
    if (this._accountKeys.receiveKeys.length === 0) throw new Error("No receive keys available in account");
    return this._accountKeys.receiveKeys[0];
  }
}
class tu extends kn {
  constructor(e, t, i) {
    super(e), this._accountIndex = t, this._accountKey = i;
  }
  // this is used in AccountStore.ts to get the key to be used in the map for this account
  getAccountStoreKey() {
    return this._bip44Account + "." + this._accountIndex;
  }
  getAccountType() {
    return Jt.VAULT_ACCOUNT;
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
    let e = await Sn([
      this._accountKey
    ]), t = [
      this._accountKey
    ].map((i) => i.tokensBalance);
    super.balance = An(e), super.tokenBalances = _n(t);
  }
  getKeyFromAddress(e) {
    if (e !== this._accountKey.address) throw new Error(`Address ${e} does not belong to this account`);
    return this._accountKey;
  }
  async getTransactions(e, t) {
    const i = t ?? this._accountKey.address;
    return this.fetchAndClassifyTransactions(i, e);
  }
  getAddresses() {
    return [
      this._accountKey
    ];
  }
  hasChangeAddresses() {
    return !1;
  }
  getPrimaryAddressKey() {
    return this._accountKey;
  }
}
const Za = 9223372036854775807n;
function ad() {
  return Math.floor(Date.now() / 1e3);
}
function Bt(r) {
  return !r || r.length === 0;
}
function nd(r) {
  return vt.isHexa(r) ? Buffer.from(r, "hex") : Ue.fromString(r).data;
}
function od(r) {
  return vt.isHexa(r) ? r : nd(r).toString("hex");
}
var Jt = /* @__PURE__ */ (function(r) {
  return r[r.NEXA_ACCOUNT = 0] = "NEXA_ACCOUNT", r[r.VAULT_ACCOUNT = 1] = "VAULT_ACCOUNT", r[r.DAPP_ACCOUNT = 2] = "DAPP_ACCOUNT", r;
})({});
function Ut(r, e, t = Ye.PayToScriptTemplate) {
  return Ue.isValid(r, e, t);
}
function Gt(r, e) {
  return r.deriveChild(e, !0);
}
function Qa(r, e, t, i, o) {
  if (e < 0) throw new Error(`Can not generate keys with fromRIndex ${e}. must be >= 0.`);
  if (i < 0) throw new Error(`Can not generate keys with fromCIndex ${i}. must be >= 0.`);
  let a = r.deriveChild(0, !1), p = r.deriveChild(1, !1), c = [], g = [];
  for (let h = e; h < t; h++) {
    let m = a.deriveChild(h, !1), S = m.privateKey.toAddress().toString();
    c.push({
      key: m,
      address: S,
      balance: "0",
      tokensBalance: {}
    });
  }
  for (let h = i; h < o; h++) {
    let m = p.deriveChild(h, !1), S = m.privateKey.toAddress().toString();
    g.push({
      key: m,
      address: S,
      balance: "0",
      tokensBalance: {}
    });
  }
  return {
    receiveKeys: c,
    changeKeys: g
  };
}
function Ni(r, e) {
  let i = r.deriveChild(0, !1).deriveChild(e, !1), o = i.privateKey.toAddress().toString();
  return {
    key: i,
    address: o,
    balance: "0",
    tokensBalance: {}
  };
}
async function Ci(r) {
  let e = -1, t = 0, i = 20;
  for (; i > 0; ) {
    i--;
    let o = r.deriveChild(t, !1).privateKey.toAddress().toString();
    await ld(o) && (e = t, i = 20), t++;
  }
  return e;
}
async function $a(r) {
  let e = r.deriveChild(0, !1), t = r.deriveChild(1, !1), i = Ci(e), o = Ci(t), [a, p] = await Promise.all([
    i,
    o
  ]);
  return {
    rIndex: a,
    cIndex: p
  };
}
async function sd(r) {
  let e = [], t = 0;
  for (; ; ) {
    const i = Gt(r, t), o = await $a(i);
    if (o.rIndex < 0 && o.cIndex < 0) break;
    o.rIndex < 0 && (o.rIndex = 0), o.cIndex < 0 && (o.cIndex = 0);
    const a = new Xa(t, o, Qa(i, o.rIndex + 1, o.rIndex + 20, o.cIndex + 1, o.cIndex + 20));
    await a.loadBalances(), e.push(a), t == 0 ? t = 100 : t++;
  }
  if (e.length == 0) {
    let i = Gt(r, 0), o = {
      rIndex: 0,
      cIndex: 0
    };
    const a = new Xa(0, o, Qa(i, o.rIndex, o.rIndex + 20, o.cIndex, o.cIndex + 20));
    await a.loadBalances(), e.push(a);
  }
  return e;
}
async function ru(r) {
  let t = Gt(r, 1).deriveChild(0, !1);
  return await Ci(t);
}
async function ud(r) {
  let e = [], t = Gt(r, 1), i = await ru(r);
  i < 0 && (i = 0);
  for (let o = 0; o <= i; o++) {
    const a = new tu(1, o, Ni(t, o));
    await a.loadBalances(), e.push(a);
  }
  return e;
}
async function iu(r) {
  let t = Gt(r, 2).deriveChild(0, !1);
  return await Ci(t);
}
async function fd(r) {
  let e = [], t = Gt(r, 2), i = await iu(r);
  i < 0 && (i = 0);
  for (let o = 0; o <= i; o++) {
    const a = new eu(2, o, Ni(t, o));
    await a.loadBalances(), e.push(a);
  }
  return e;
}
async function cd(r) {
  let e = [];
  const t = await sd(r), i = await ud(r), o = await fd(r);
  return e = e.concat(t), e = e.concat(i), e = e.concat(o), e;
}
async function ld(r) {
  try {
    let e = await zt.getFirstUse(r);
    return e.tx_hash && e.tx_hash !== "";
  } catch (e) {
    if (e instanceof Error && e.message.includes("not found")) return !1;
    throw e;
  }
}
async function hd(r) {
  let e = await zt.getTokensBalance(r.address), t = {};
  for (const i in e.confirmed) e.confirmed[i] != 0 && (t[i] = {
    confirmed: BigInt(e.confirmed[i]).toString(),
    unconfirmed: "0"
  });
  for (const i in e.unconfirmed) e.unconfirmed[i] != 0 && (t[i] ? t[i].unconfirmed = BigInt(e.unconfirmed[i]).toString() : t[i] = {
    confirmed: "0",
    unconfirmed: BigInt(e.unconfirmed[i]).toString()
  });
  return t;
}
async function dd(r) {
  let e = await zt.getBalance(r.address);
  return r.balance = (BigInt(e.confirmed) + BigInt(e.unconfirmed)).toString(), r.tokensBalance = await hd(r), e;
}
async function Sn(r) {
  let e = [];
  return r.forEach((t) => {
    let i = dd(t);
    e.push(i);
  }), await Promise.all(e);
}
function An(r) {
  let e = new Pt(0), t = new Pt(0);
  return r.forEach((i) => {
    e = e.add(new Pt(i.confirmed)), t = t.add(new Pt(i.unconfirmed));
  }), {
    confirmed: e.getValue(),
    unconfirmed: t.getValue()
  };
}
function _n(r) {
  let e = {};
  return r.forEach((t) => {
    for (const i in t) e[i] ? (e[i].confirmed = (BigInt(e[i].confirmed) + BigInt(t[i].confirmed)).toString(), e[i].unconfirmed = (BigInt(e[i].unconfirmed) + BigInt(t[i].unconfirmed)).toString()) : e[i] = {
      confirmed: t[i].confirmed,
      unconfirmed: t[i].unconfirmed
    };
  }), e;
}
async function Ii(r, e) {
  let t = 0, i = 0, o = /* @__PURE__ */ new Map(), a = e;
  for (let p of r) {
    i++;
    let c = await zt.getTransactionHistory(p);
    if (c && c.length > 0) {
      t = i;
      for (let g of c) (g.height === 0 || g.height > e) && (a = Math.max(a, g.height), o.set(g.tx_hash, g));
    }
  }
  return {
    index: t,
    txs: o,
    lastHeight: a
  };
}
async function pd(r, e) {
  if (r == 0) {
    let t = Gt(e, 0);
    const i = await $a(t);
    if (i.rIndex < 0 && i.cIndex < 0) return 0;
    for (let o = 100; ; o++) {
      const a = Gt(e, o), p = await $a(a);
      if (p.rIndex < 0 && p.cIndex < 0) return o;
    }
  } else {
    if (r == 1)
      return await ru(e) + 1;
    if (r == 2)
      return await iu(e) + 1;
    throw new Error("Can not get next account index. Invalid accountType.");
  }
}
async function en(r, e) {
  let t = await zt.getTransaction(r.tx_hash), i = t.vout.filter((M) => !ze(M.scriptPubKey.addresses)), o = t.vin.length > 0 && e.includes(t.vin[0].addresses[0]), a = !o || i.every((M) => e.includes(M.scriptPubKey.addresses[0])), p = t.height > 0, c = {};
  if (c.txId = t.txid, c.txIdem = t.txidem, c.height = p ? t.height : 0, c.time = p ? t.time : ad(), c.fee = t.fee_satoshi, o && a)
    c.state = "both", c.value = "0", c.payTo = "Payment to yourself";
  else if (a) {
    c.state = "incoming";
    let M = i.filter((_) => e.includes(_.scriptPubKey.addresses[0])), I = new Pt(0);
    M.forEach((_) => {
      I = I.add(new Pt(_.value_satoshi));
    }), c.value = I.getValue(), c.payTo = M[0].scriptPubKey.addresses[0];
  } else if (o) {
    c.state = "outgoing";
    let M = i.filter((_) => !e.includes(_.scriptPubKey.addresses[0])), I = new Pt(0);
    M.forEach((_) => {
      I = I.add(new Pt(_.value_satoshi));
    }), c.value = I.getValue(), c.payTo = M[0].scriptPubKey.addresses[0];
  }
  let [g, h, m, S] = md(t.vin, i, c.state, e);
  return c.txGroupType = g, c.token = h, c.tokenAmount = m, c.extraGroup = S, c;
}
function md(r, e, t, i) {
  let o = r.filter((_) => !Bt(_.group)), a = e.filter((_) => !Bt(_.scriptPubKey.group));
  if (Bt(o) && Bt(a)) return [
    0,
    "none",
    "0",
    "none"
  ];
  let p = o.filter((_) => i.includes(_.addresses[0])), c = a.filter((_) => i.includes(_.scriptPubKey.addresses[0]));
  if (Bt(p) && Bt(c)) return [
    0,
    "none",
    "0",
    "none"
  ];
  if (Bt(o))
    return [
      1,
      c.find((E) => BigInt(E.scriptPubKey.groupQuantity) < 0n)?.scriptPubKey.group ?? "none",
      "0",
      "none"
    ];
  if (Bt(a)) {
    if (t === "incoming") return [
      0,
      "none",
      "0",
      "none"
    ];
    let _ = p.filter((N) => BigInt(N.groupQuantity) > 0n);
    if (!Bt(_)) {
      let N = new Pt(0);
      _.forEach((F) => {
        N = N.add(new Pt(F.groupQuantity));
      });
      let U = _[0].group, j = p.find((F) => BigInt(F.groupQuantity) < 0n && _[0].group != F.group)?.group ?? "none";
      return [
        3,
        U,
        N.getValue(),
        j
      ];
    }
    let E = p.find((N) => BigInt(N.groupQuantity) < 0n)?.group ?? "none", O = p.find((N) => BigInt(N.groupQuantity) < 0n && E != N.group)?.group ?? "none";
    return [
      3,
      E,
      "0",
      O
    ];
  }
  let g = o.filter((_) => BigInt(_.groupQuantity) > 0n), h = a.filter((_) => BigInt(_.scriptPubKey.groupQuantity) > 0n);
  if (Bt(g) && Bt(h)) {
    let _ = o.find((O) => BigInt(O.groupQuantity) < 0n)?.group ?? "none", E = a.find((O) => BigInt(O.scriptPubKey.groupQuantity) < 0n && _ != O.scriptPubKey.group)?.scriptPubKey.group ?? "none";
    return [
      4,
      E !== "none" ? E : _,
      "0",
      E !== "none" ? _ : E
    ];
  }
  if (Bt(g)) {
    let _ = h[0].scriptPubKey.group, E = new Pt(0);
    h.forEach((N) => {
      E = E.add(new Pt(N.scriptPubKey.groupQuantity));
    });
    let O = o.find((N) => BigInt(N.groupQuantity) < 0n && _ != N.group)?.group ?? "none";
    return [
      2,
      _,
      E.getValue(),
      O
    ];
  }
  if (Bt(h)) {
    let _ = g[0].group, E = new Pt(0);
    g.forEach((N) => {
      E = E.add(new Pt(N.groupQuantity));
    });
    let O = o.find((N) => BigInt(N.groupQuantity) < 0n && _ != N.group)?.group ?? "none";
    return [
      3,
      _,
      E.getValue(),
      O
    ];
  }
  let m = h.map((_) => BigInt(_.scriptPubKey.groupQuantity)).reduce((_, E) => _ + E, 0n), S = g.map((_) => BigInt(_.groupQuantity)).reduce((_, E) => _ + E, 0n);
  if (m > S) {
    let _ = h[0].scriptPubKey.group, E = o.find((O) => BigInt(O.groupQuantity) < 0n && _ != O.group)?.group ?? "none";
    return [
      2,
      _,
      (m - S).toString(),
      E
    ];
  }
  if (S > m) {
    let _ = g[0].group, E = o.find((O) => BigInt(O.groupQuantity) < 0n && _ != O.group)?.group ?? "none";
    return [
      3,
      _,
      (S - m).toString(),
      E
    ];
  }
  let M = h[0].scriptPubKey.group, I = "";
  return t === "incoming" ? I = h.filter((_) => i.includes(_.scriptPubKey.addresses[0])).map((_) => BigInt(_.scriptPubKey.groupQuantity)).reduce((_, E) => _ + E, 0n).toString() : t === "outgoing" ? I = h.filter((_) => !i.includes(_.scriptPubKey.addresses[0])).map((_) => BigInt(_.scriptPubKey.groupQuantity)).reduce((_, E) => _ + E, 0n).toString() : I = "0", [
    5,
    M,
    I,
    "none"
  ];
}
class ei {
  static getAllKeys(e) {
    return e.receiveKeys.concat(e.changeKeys);
  }
  static getAllAddresses(e) {
    return ei.getAllKeys(e).map((t) => t.address);
  }
}
function au(r, e) {
  if (r > 0) return !1;
  let t = BigInt.asUintN(64, BigInt(r));
  switch (e) {
    case "authorise":
      return ge.allowsRenew(t);
    case "mint":
      return ge.allowsMint(t);
    case "melt":
      return ge.allowsMelt(t);
    case "rescript":
      return ge.allowsRescript(t);
    case "subgroup":
      return ge.allowsSubgroup(t);
    default:
      return !1;
  }
}
function tn(r, e = !0) {
  if (r > 0) return 0n;
  let t = BigInt.asUintN(64, BigInt(r)), i = ge.authFlags.AUTHORITY;
  return ge.allowsRenew(t) && (i |= ge.authFlags.BATON), ge.allowsMint(t) && (i |= ge.authFlags.MINT), ge.allowsMelt(t) && (i |= ge.authFlags.MELT), ge.allowsRescript(t) && (i |= ge.authFlags.RESCRIPT), ge.allowsSubgroup(t) && e && (i |= ge.authFlags.SUBGROUP), i;
}
const rn = 250;
async function bd(r, e, t, i) {
  let o = e.receiveKeys.filter((m) => BigInt(m.balance) > 0n), a = e.changeKeys.filter((m) => BigInt(m.balance) > 0n), p = o.concat(a);
  if (Bt(p)) throw new Error("Not enough Nexa balance.");
  let c = /* @__PURE__ */ new Map(), g = i.isConsolidate ? 0 : Number(t);
  for (let m of p) {
    let S = await zt.getNexaUtxos(m.address);
    for (let M of S) {
      let I = {
        outpoint: M.outpoint_hash,
        address: m.address,
        satoshis: M.value,
        templateData: i.templateData
      };
      if (r.from(I), c.has(m.address) || c.set(m.address, m.key.privateKey), i.isConsolidate) {
        if (r.change(i.toChange ?? e.receiveKeys[e.receiveKeys.length - 1].address), r.transaction.inputs.length > rn) return Array.from(c.values());
      } else {
        let _ = r.transaction;
        if (_.inputs.length > rn) throw new Error("Too many inputs. Consider consolidate transactions or reduce the send amount.");
        let E = _.getUnspentValue();
        if (E < 0n) continue;
        if (E == 0n && i.feeFromAmount) {
          let N = _.estimateRequiredFee();
          return _.updateOutputAmount(0, g - N), Array.from(c.values());
        }
        const O = i.toChange ?? (e.changeKeys.length > 0 ? e.changeKeys[e.changeKeys.length - 1].address : e.receiveKeys[e.receiveKeys.length - 1].address);
        if (r.change(O), i.feeFromAmount) {
          let N = _.getChangeOutput(), U = _.estimateRequiredFee();
          _.updateOutputAmount(0, g - U), !N && _.getChangeOutput() && (U = _.estimateRequiredFee(), _.updateOutputAmount(0, g - U));
        }
        if (_.getUnspentValue() < _.estimateRequiredFee()) continue;
        return Array.from(c.values());
      }
    }
  }
  if (i.isConsolidate) {
    if (c.size > 0) return Array.from(c.values());
    throw new Error("Not enough Nexa balance.");
  }
  let h = {
    errorMsg: "Not enough Nexa balance.",
    amount: zi.formatNEXA(r.transaction.outputs[0].value),
    fee: zi.formatNEXA(r.transaction.estimateRequiredFee())
  };
  throw new Error(JSON.stringify(h));
}
async function vd(r, e, t, i) {
  let o = od(t), a = e.receiveKeys.filter((m) => Object.keys(m.tokensBalance).includes(o)), p = e.changeKeys.filter((m) => Object.keys(m.tokensBalance).includes(o)), c = a.concat(p);
  if (Bt(c)) throw new Error("Not enough token balance.");
  let g = /* @__PURE__ */ new Map(), h = 0n;
  for (let m of c) {
    let S = await zt.getTokenUtxos(m.address, t);
    for (let M of S)
      if (!(M.token_amount < 0)) {
        if (r.from({
          outpoint: M.outpoint_hash,
          address: m.address,
          satoshis: M.value,
          groupId: M.group,
          groupAmount: BigInt(M.token_amount)
        }), h = h + BigInt(M.token_amount), g.has(m.address) || g.set(m.address, m.key.privateKey), h > Za) throw new Error("Token inputs exceeded max amount. Consider sending in small chunks");
        if (r.transaction.inputs.length > rn) throw new Error("Too many inputs. Consider consolidating transactions or reduce the send amount.");
        if (h == i) return Array.from(g.values());
        if (h > i) {
          const I = e.changeKeys.length > 0 ? e.changeKeys[e.changeKeys.length - 1].address : e.receiveKeys[e.receiveKeys.length - 1].address;
          return r.to(I, Le.DUST_AMOUNT, t, h - i), Array.from(g.values());
        }
      }
  }
  throw new Error("Not enough token balance");
}
async function gd(r, e, t, i) {
  const o = ei.getAllKeys(e);
  let a = "", p = [], c;
  for (let g of o) {
    let h = await zt.getNexaUtxos(g.address);
    for (let m of h)
      if (r.from({
        outpoint: m.outpoint_hash,
        address: g.address,
        satoshis: m.value
      }), Bt(a)) {
        a = m.outpoint_hash;
        let S = ge.findGroupId(a, Buffer.from(t, "hex"), ge.authFlags.ACTIVE_FLAG_BITS);
        const M = new Ue(S.hashBuffer, i, Ye.GroupIdAddress).toString();
        return r.to(e.receiveKeys.at(-1).address, Le.DUST_AMOUNT, M, ge.authFlags.ACTIVE_FLAG_BITS | S.nonce), c = g.key.privateKey, p.push(c), p;
      }
  }
  throw new Error("Not enough Nexa balance.");
}
async function yd(r, e, t) {
  let i = await zt.getUtxo(t), o = i.addresses[0];
  r.from({
    outpoint: t,
    address: o,
    satoshis: i.amount
  });
  let p = ei.getAllKeys(e).find((c) => c.address === o);
  if (!p) throw new Error("UTXO associated key not found in the wallet");
  return [
    p.key.privateKey
  ];
}
async function is(r, e, t, i, o = "", a = "", p) {
  let c = ei.getAllKeys(e);
  for (let g of c) {
    let h = await zt.getTokenUtxos(g.address, t);
    for (let m of h)
      if (au(m.token_amount, i)) {
        if (r.from({
          outpoint: m.outpoint_hash,
          address: g.address,
          satoshis: m.value
        }), i === "subgroup") {
          const S = p ?? tn(m.token_amount, !1);
          r.to(a, Le.DUST_AMOUNT, o, S);
        }
        if (ge.allowsRenew(BigInt.asUintN(64, BigInt(m.token_amount)))) {
          const S = e.changeKeys.length > 0 ? e.changeKeys[e.changeKeys.length - 1].address : e.receiveKeys[e.receiveKeys.length - 1].address;
          r.to(S, Le.DUST_AMOUNT, t, tn(m.token_amount));
        }
        return [
          g.key.privateKey
        ];
      }
  }
  throw new Error("The requested authority not found");
}
async function wd(r, e, t, i, o) {
  let a = ei.getAllKeys(e), p = [], c = new Set(i);
  c.add("authorise");
  for (let g of a) {
    let h = await zt.getTokenUtxos(g.address, t);
    for (let m of h) {
      if (m.token_amount > 0) continue;
      let S = !1;
      for (let I of c) au(m.token_amount, I) && (c.delete(I), S = !0);
      if (!S) continue;
      r.from({
        outpoint: m.outpoint_hash,
        address: g.address,
        satoshis: m.value
      }), p.push(g.key.privateKey);
      const M = o ?? (e.changeKeys.length > 0 ? e.changeKeys[e.changeKeys.length - 1].address : e.receiveKeys[e.receiveKeys.length - 1].address);
      if (r.to(M, Le.DUST_AMOUNT, t, tn(m.token_amount)), c.size === 0) return p;
    }
  }
  throw new Error("The required authorities not found");
}
class xd {
  /**
   * Creates a new TransactionCreator instance
   * @param tx Optional existing TransactionBuilder, hex string, or buffer
   */
  constructor(e) {
    this._builder = [], this._totalValue = BigInt(0), this._network = Rt.mainnet, this._txOptions = {}, e instanceof Jr && (this.transactionBuilder = e), this.tokens = /* @__PURE__ */ new Set(), this.transactionBuilder = new Jr();
  }
  /**
   * Parse transaction from hex string with common logic
   * @param tx Transaction hex string
   * @returns This instance for chaining
   */
  parseTxHex(e) {
    return this.builder = [], this.builder.push(async () => {
      try {
        const t = new Jr(e), i = new Jr(), o = t.transaction.inputs;
        for (let a = 0; a < o.length; a++) {
          const p = o[a], c = await zt.getUtxo(p.outpoint.toString("hex")), g = ee.fromHex(c.scriptpubkey);
          if (g.isScriptTemplateOut()) {
            const h = p.scriptSig;
            i.transaction.addInput(new Lr({
              amount: p.amount,
              outpoint: p.outpoint.toString("hex"),
              scriptSig: p.scriptSig,
              templateData: {
                templateScript: W.isHashBuffer(g.getTemplateHash()) ? ee.fromBuffer(h.chunks[0].buf) : ee.empty(),
                constraintScript: W.isHashBuffer(g.getConstraintHash()) ? ee.fromBuffer(h.chunks[1].buf) : $.OP_FALSE
              },
              output: {
                type: p.type,
                value: c.amount,
                scriptPubKey: c.scriptpubkey
              }
            }));
          } else
            i.from({
              outpoint: p.outpoint.toString("hex"),
              satoshis: p.amount,
              address: c.addresses[0],
              scriptPubKey: c.scriptpubkey
            });
          await this.handleParsedInput(p, c, a);
        }
        i.transaction.outputs = t.transaction.outputs, this.transactionBuilder = i, await this.handleParsingComplete();
      } catch (t) {
        throw console.error("parseTxHex: Error parsing transaction:", t), t;
      }
    }), this;
  }
  /**
   * Hook for subclasses to handle individual parsed inputs
   * @param input The original input from the transaction
   * @param utxo UTXO data for this input
   * @param index Input index
   */
  async handleParsedInput(e, t, i) {
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
  onNetwork(e) {
    return this.network = Rt.get(e), this;
  }
  /** Gets transaction options */
  get txOptions() {
    return this._txOptions;
  }
  /** Sets transaction options */
  set txOptions(e) {
    this._txOptions = e;
  }
  /** Gets the network for this transaction */
  get network() {
    return this._network;
  }
  /** Sets the network for this transaction */
  set network(e) {
    this._network = e;
  }
  /** Gets the builder function array */
  get builder() {
    return this._builder;
  }
  /** Sets the builder function array */
  set builder(e) {
    this._builder = e;
  }
  /** Gets the underlying transaction builder */
  get transactionBuilder() {
    return this._transactionBuilder;
  }
  /** Sets the underlying transaction builder */
  set transactionBuilder(e) {
    this._transactionBuilder = e;
  }
  /** Gets the set of token actions */
  get tokens() {
    return this._tokens;
  }
  /** Sets the set of token actions */
  set tokens(e) {
    this._tokens = e;
  }
  /** Gets the total NEXA value being sent */
  get totalValue() {
    return this._totalValue;
  }
  /** Sets the total NEXA value being sent */
  set totalValue(e) {
    this._totalValue = e;
  }
  /**
   * Validates and creates a token action
   * @param toAddr Destination address
   * @param amount Amount to send
   * @param token Token ID
   * @param action Action type (mint, melt, send, etc.)
   * @throws Error if validation fails
   */
  tokenAction(e, t, i, o) {
    if (!Ut(e, this.network) && !Ut(e, this.network, Ye.PayToPublicKeyHash)) throw new Error("Invalid Address.");
    if (i && BigInt(t) < 1n || !i && Dn(t) < Le.DUST_AMOUNT) throw new Error("The amount is too low.");
    if (i && BigInt(t) > Za || !i && Dn(t) > Le.MAX_MONEY) throw new Error("The amount is too high.");
    if (!Ut(i, this.network, Ye.GroupIdAddress)) throw new Error("Invalid Token ID");
    if (Ue.getOutputType(e) === 0) throw new Error("Token must be sent to script template address");
    this.transactionBuilder.to(e, Le.DUST_AMOUNT, i, BigInt(t)), this.tokens.add({
      token: i,
      amount: BigInt(t),
      action: o
    });
  }
  /**
   * Configures transaction to consolidate UTXOs to a single address
   * @param toAddr Address to consolidate funds to
   * @returns This instance for chaining
   */
  consolidate(e) {
    return this.builder.push(async () => {
      if (!Ut(e, this.network) && !Ut(e, this.network, Ye.PayToPublicKeyHash)) throw new Error("Invalid Address.");
      this._txOptions.isConsolidate = !0, this._txOptions.toChange = e;
    }), this;
  }
  /**
   * Configures transaction to deduct fee from the send amount
   * @returns This instance for chaining
   */
  feeFromAmount() {
    return this.builder.push(async () => {
      this._txOptions.feeFromAmount = !0;
    }), this;
  }
  /**
   * Adds a token send operation to the transaction
   * @param toAddr Destination address
   * @param amount Amount of tokens to send
   * @param token Token ID
   * @param dustAmount Optional dust amount for the output (defaults to Transaction.DUST_AMOUNT)
   * @returns This instance for chaining
   */
  sendToToken(e, t, i, o = Le.DUST_AMOUNT) {
    return this.builder.push(async () => {
      if (!Ut(e, this.network) && !Ut(e, this.network, Ye.PayToPublicKeyHash)) throw new Error("Invalid Address.");
      if (BigInt(t) < 1n) throw new Error("The amount is too low.");
      if (BigInt(t) > Za) throw new Error("The amount is too high.");
      if (!Ut(i, this.network, Ye.GroupIdAddress)) throw new Error("Invalid Token ID");
      if (Ue.getOutputType(e) === 0) throw new Error("Token must be sent to script template address");
      this.transactionBuilder.to(e, o, i, BigInt(t)), this.tokens.add({
        token: i,
        amount: BigInt(t),
        action: "send"
      });
    }), this;
  }
  /**
   * Adds a NEXA send operation to the transaction
   * @param toAddr Destination address
   * @param amount Amount of NEXA to send
   * @returns This instance for chaining
   */
  sendTo(e, t) {
    return this.builder.push(async () => {
      if (!Ut(e, this.network) && !Ut(e, this.network, Ye.PayToPublicKeyHash)) throw new Error("Invalid Address.");
      this.transactionBuilder.to(e, t), this.totalValue = BigInt(this.totalValue + t);
    }), this;
  }
  /**
   * Adds a token authority renewal operation
   * @param token Token ID to renew authority for
   * @param perms Permissions to renew
   * @param toAddr
   * @returns This instance for chaining
   */
  renewAuthority(e, t, i) {
    return this.builder.push(async () => {
      if (i != null && !Ut(i, this.network) && !Ut(i, this.network, Ye.PayToPublicKeyHash))
        throw new Error("Invalid Address.");
      this.tokens.add({
        token: e,
        action: "renew",
        amount: BigInt(Le.DUST_AMOUNT),
        parentToken: void 0,
        extraData: {
          perms: t,
          address: i
        }
      });
    }), this;
  }
  /**
   * Adds a token authority deletion operation
   * @param token Token ID to delete authority for
   * @param outpoint Outpoint of the authority to delete
   * @returns This instance for chaining
   */
  deleteAuthority(e, t) {
    return this.builder.push(async () => {
      this.tokens.add({
        token: e,
        action: "delete",
        amount: BigInt(Le.DUST_AMOUNT),
        parentToken: void 0,
        extraData: {
          outpoint: t
        }
      });
    }), this;
  }
  /**
   * Creates a legacy token (not implemented)
   * @returns This instance for chaining
   */
  legacyToken(e, t, i, o, a) {
    return this.builder.push(async () => {
      const p = Et.buildTokenDescriptionLegacy(t, e, o, a, i);
      this.transactionBuilder.addData(p, !0), this.tokens.add({
        action: "group",
        amount: BigInt(Le.DUST_AMOUNT),
        extraData: {
          opReturnData: p.toHex()
        }
      });
    }), this;
  }
  /**
   * Creates a legacy group (not implemented)
   * @returns This instance for chaining
   */
  legacyGroup(e, t, i, o) {
    return this.builder.push(async () => {
      const a = Et.buildTokenDescriptionLegacy(t, e, i, o);
      this.transactionBuilder.addData(a, !0), this.tokens.add({
        action: "group",
        amount: BigInt(Le.DUST_AMOUNT),
        extraData: {
          opReturnData: a.toHex()
        }
      });
    }), this;
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
  token(e, t, i, o, a) {
    return this.builder.push(async () => {
      const p = Et.buildTokenDescription(t, e, o, a, i);
      this.transactionBuilder.addData(p, !0), this.tokens.add({
        action: "group",
        amount: BigInt(Le.DUST_AMOUNT),
        extraData: {
          opReturnData: p.toHex()
        }
      });
    }), this;
  }
  /**
   * Creates an NFT collection with metadata
   * @param name Collection name
   * @param ticker Collection ticker symbol
   * @param docUrl URL to collection documentation
   * @param docHash Hash of collection documentation
   * @returns This instance for chaining
   */
  collection(e, t, i, o) {
    return this.builder.push(async () => {
      const a = Et.buildNFTCollectionDescription(t, e, i, o);
      this.transactionBuilder.addData(a, !0), this.tokens.add({
        action: "group",
        amount: BigInt(Le.DUST_AMOUNT),
        extraData: {
          opReturnData: a.toHex()
        }
      });
    }), this;
  }
  /**
   * Creates an NFT within a collection
   * @param parent Parent collection token ID
   * @param zipUrl URL to NFT content ZIP file
   * @param zipHash Hash of NFT content ZIP file
   * @returns This instance for chaining
   */
  nft(e, t, i) {
    return this.builder.push(async () => {
      let o = Et.buildNFTDescription(t, i);
      this.transactionBuilder.addData(o, !0);
      const a = ge.generateSubgroupId(e, i), p = new Ue(a, Rt.get(this.network) || Rt.mainnet, Ye.GroupIdAddress).toString();
      this.tokens.add({
        token: p,
        parentToken: e,
        amount: BigInt(Le.DUST_AMOUNT),
        action: "subgroup",
        extraData: {
          quantity: 1n
        }
      });
    }), this;
  }
  /**
   * Creates an SFT (Semi-Fungible Token) within a collection with specified quantity
   * @param parent Parent collection token ID
   * @param zipUrl URL to SFT content ZIP file
   * @param zipHash Hash of SFT content ZIP file
   * @param quantity Quantity of SFTs to create
   * @returns This instance for chaining
   */
  sft(e, t, i, o) {
    return this.builder.push(async () => {
      let a = Et.buildNFTDescription(t, i);
      this.transactionBuilder.addData(a, !0);
      const p = ge.generateSubgroupId(e, i), c = new Ue(p, Rt.get(this.network) || Rt.mainnet, Ye.GroupIdAddress).toString();
      this.tokens.add({
        token: c,
        parentToken: e,
        amount: BigInt(Le.DUST_AMOUNT),
        action: "subgroup",
        extraData: {
          quantity: o
        }
      });
    }), this;
  }
  /**
   * Adds an OP_RETURN output to the transaction
   * @param data Data to include in the OP_RETURN
   * @param isFullScript Whether the data is already a complete script
   * @returns This instance for chaining
   */
  addOpReturn(e, t = !1) {
    return this.builder.push(async () => {
      let i = t ? new ee(e) : Et.buildDataOut(e), o = new kt(0, i);
      this.transactionBuilder.transaction.addOutput(o);
    }), this;
  }
  /**
   * Adds nexa contract constraint to spending inputs
   * @param templateScript
   * @param constraintScript
   * @param visibleArgs
   * @param pubKey
   * @returns This instance for chaining
   */
  addContract(e, t, i, o) {
    return this.builder.push(async () => {
      this.txOptions.templateData = {
        publicKey: o,
        templateScript: e,
        constraintScript: t,
        visibleArgs: i
      };
    }), this;
  }
  /**
   * Builds the transaction by executing all queued operations
   * @returns Promise resolving to the serialized transaction hex
   */
  async build() {
    for (const e of this.builder) await e();
    return this.transactionBuilder.transaction.serialize({
      disableAll: !0
    });
  }
}
class Ai extends xd {
  constructor(e, t) {
    super(t), this._keysToSign = [], this._account = e, this.validateAccount();
  }
  fromAccount(e) {
    return this._account = e, this;
  }
  parseTxHex(e) {
    return super.parseTxHex(e);
  }
  /**
   * Handle wallet-specific logic for each parsed input (find and store private keys)
   */
  async handleParsedInput(e, t, i) {
    const o = this.findPrivateKeyFromAddress(t.addresses[0]);
    o && this._keysToSign.push(o.key.privateKey);
  }
  /**
   * Handle wallet-specific post-processing after parsing is complete
   */
  async handleParsingComplete() {
    this._keysToSign.length == 0 && this._keysToSign.push(this._account.getPrimaryAddressKey().key.privateKey);
  }
  parseTxBuffer(e) {
    this.builder = [], this.transactionBuilder = new Jr(e);
    const t = this._account.getAddresses();
    for (const i of t) this._keysToSign.includes(i.key.privateKey) || this._keysToSign.push(i.key.privateKey);
    return this._keysToSign.length == 0 && this._keysToSign.push(this._account.getPrimaryAddressKey().key.privateKey), this;
  }
  mint(e, t) {
    return this.builder.push(async () => {
      let i = this._account.accountKeys.receiveKeys.at(-1).address;
      this.tokenAction(i, t, e, "mint");
    }), this;
  }
  melt(e, t) {
    return this.builder.push(async () => {
      let i = this._account.accountKeys.receiveKeys.at(-1).address;
      this.tokenAction(i, t, e, "melt");
    }), this;
  }
  populate() {
    return this.validateAccount(), this.builder.push(async () => {
      let e = [], t = [];
      if (this.tokens.size > 0) for (const i of this.tokens)
        i.action == "mint" || i.action == "melt" ? e = e.concat(await is(this.transactionBuilder, this._account.accountKeys, i.token, i.action)) : i.action == "group" ? e = e.concat(await gd(this.transactionBuilder, this._account.accountKeys, i.extraData?.opReturnData, this.network)) : i.action == "subgroup" ? e = e.concat(await is(this.transactionBuilder, this._account.accountKeys, i.parentToken, "subgroup", i.token, this._account.accountKeys.receiveKeys.at(-1).address, i.extraData?.quantity)) : i.action == "renew" ? e = e.concat(await wd(this.transactionBuilder, this._account.accountKeys, i.token, i.extraData.perms, i.extraData.address)) : i.action == "delete" ? e = e.concat(await yd(this.transactionBuilder, this._account.accountKeys, i.extraData.outpoint)) : e = e.concat(await vd(this.transactionBuilder, this._account.accountKeys, i.token, i.amount)), this._keysToSign.concat(e);
      t = t.concat(await bd(this.transactionBuilder, this._account.accountKeys, this.totalValue, this.txOptions)), this._keysToSign = e.concat(t);
    }), this;
  }
  sign() {
    return this.builder.push(async () => {
      const e = await zt.getBlockTip();
      this.transactionBuilder.lockUntilBlockHeight(e.height);
      const t = this.transactionBuilder.transaction.inputs;
      for (let i = 0; i < t.length; i++) {
        const o = t[i], a = this.analyzeScriptSig(o.scriptSig);
        if (a.strategy === "skip") {
          console.log(`Skipping input ${i} - no placeholder found`);
          continue;
        }
        const p = a.sighashType || new Vt();
        let c = !1;
        const g = this._account.getAddresses();
        for (const h of g) try {
          const m = qa.sign(this.transactionBuilder.transaction, i, p, this.transactionBuilder.transaction.inputs[i].getSubscript(), h.key.privateKey), S = new oi({
            publicKey: h.key.publicKey,
            sigType: p,
            signature: m,
            subscript: this.transactionBuilder.transaction.inputs[i].getSubscript(),
            inputIndex: i
          }).toTxSatisfier();
          if (a.strategy === "sign_all") this.transactionBuilder.signInput(i, h.key.privateKey, p);
          else if (a.strategy === "replace_placeholder" && a.placeholderIndex !== void 0)
            if (o instanceof Lr && a.satisfierElements && a.satisfierElements.length > 0) {
              const M = o, I = [
                ...a.satisfierElements
              ], _ = a.placeholderIndex - 2;
              I.splice(_, 0, S), this.transactionBuilder.transaction.inputs[i].scriptSig = this.buildScriptSig(M.templateScript, M.constraintScript, I);
            } else if (o instanceof Lr) {
              const M = o;
              this.transactionBuilder.transaction.inputs[i].scriptSig = this.buildScriptSig(M.templateScript, M.constraintScript, [
                S
              ]);
            } else
              this.transactionBuilder.transaction.inputs[i].scriptSig = Et.buildPublicKeyHashIn(h.key.publicKey, m);
          c = !0;
          break;
        } catch {
        }
      }
    }), this;
  }
  buildSatisfier(e) {
    let t = new ee();
    for (const i of e) t = t.add(i);
    return t;
  }
  buildScriptSig(e, t, i) {
    const o = this.buildSatisfier(i);
    return Et.buildScriptTemplateIn(e, t, o);
  }
  /**
   * Check if a buffer is a 64-byte placeholder (all zeros)
   * @param buf - Buffer to check
   * @returns true if it's a 64-byte zero placeholder
   */
  isPlaceholder(e) {
    if (!e || e.length < 64) return !1;
    const t = Buffer.alloc(64, 0);
    return e.subarray(0, 64).equals(t);
  }
  /**
   * Extract sighash type from placeholder buffer (bytes after the 64-byte placeholder)
   * @param buf - Buffer that may contain sighash type after placeholder
   * @returns SighashType or null if using default SIGHASH_ALL (empty sighash = 0)
   */
  extractSighashFromPlaceholder(e) {
    if (e.length <= 64)
      return Vt.ALL;
    const t = e.subarray(64);
    if (t.length === 0) return Vt.ALL;
    const i = t[0], o = i >> 4 & 15, a = i & 15, p = new Vt();
    let c = 1;
    switch (o) {
      case 0:
        p.inType = 0;
        break;
      case 1:
        p.inType = 1, c < t.length && (p.inData = [
          t[c]
        ], c++);
        break;
      case 2:
        p.inType = 2;
        break;
      default:
        p.inType = 0;
    }
    switch (a) {
      case 0:
        p.outType = 0;
        break;
      case 1:
        p.outType = 1, c < t.length && (p.outData = [
          t[c]
        ], c++);
        break;
      case 2:
        p.outType = 2;
        const g = [];
        c < t.length && (g.push(t[c]), c++), c < t.length && (g.push(t[c]), c++), p.outData = g;
        break;
      default:
        p.outType = 0;
    }
    return p;
  }
  /**
   * Determine signing behavior based on scriptSig content
   * @param scriptSig - The scriptSig to analyze
   * @returns Object with signing strategy and sighash type
   */
  analyzeScriptSig(e) {
    const t = e.chunks;
    if (t.length === 0) return {
      strategy: "sign_all",
      sighashType: null
    };
    if (t.length === 1) {
      const i = t[0];
      return i.buf && this.isPlaceholder(i.buf) ? {
        strategy: "sign_all",
        sighashType: this.extractSighashFromPlaceholder(i.buf)
      } : {
        strategy: "skip",
        sighashType: null
      };
    }
    if (t.length >= 3) {
      const i = [];
      let o, a = null;
      for (let p = 2; p < t.length; p++) {
        const c = t[p];
        c.buf && this.isPlaceholder(c.buf) ? (o = p, a = this.extractSighashFromPlaceholder(c.buf)) : i.push({
          buf: c.buf,
          len: c.len || (c.buf ? c.buf.length : 0),
          opcodenum: c.opcodenum
        });
      }
      if (o !== void 0) return {
        strategy: "replace_placeholder",
        sighashType: a,
        placeholderIndex: o,
        satisfierElements: i
      };
    }
    for (let i = 0; i < t.length; i++) {
      const o = t[i];
      if (o.buf && this.isPlaceholder(o.buf))
        return {
          strategy: "replace_placeholder",
          sighashType: this.extractSighashFromPlaceholder(o.buf),
          placeholderIndex: i
        };
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
  findPrivateKeyFromAddress(e) {
    return this._account.getAddresses().find((i) => i.address === e);
  }
}
class kd {
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
  getAccountStoreKey(e, t) {
    switch (e) {
      case Jt.DAPP_ACCOUNT:
        return e + "." + t;
      case Jt.VAULT_ACCOUNT:
        return e + "." + t;
      default:
        return String(t);
    }
  }
  /**
   * Creates a new account of the specified type
   * @param accountType Type of account to create (DAPP, VAULT, or DEFAULT)
   * @param masterKey Master HD private key for deriving account keys
   * @returns Promise resolving to the created account
   */
  async createAccount(e, t) {
    const i = await pd(e, t), o = this.getAccountStoreKey(e, i), a = this._accounts.get(String(o));
    if (a) return a;
    switch (e) {
      case Jt.DAPP_ACCOUNT:
        let p = Gt(t, 2);
        const c = new eu(2, i, Ni(p, i));
        return await c.loadBalances(), this._accounts.set(c.getAccountStoreKey(), c), c;
      case Jt.VAULT_ACCOUNT:
        let g = Gt(t, 1);
        const h = new tu(1, i, Ni(g, i));
        return await h.loadBalances(), this._accounts.set(h.getAccountStoreKey(), h), h;
      default:
        let m = Gt(t, i);
        const S = {
          rIndex: 0,
          cIndex: 0
        }, M = new Xa(i, S, Qa(m, S.rIndex + 1, S.rIndex + 20, S.cIndex + 1, S.cIndex + 20));
        return await M.loadBalances(), this._accounts.set(M.getAccountStoreKey(), M), M;
    }
  }
  /**
   * Finds the private key associated with a given address across all accounts
   * @param address The address to search for
   * @returns The AddressKey containing the private key, or null if not found
   */
  findKeyForAddress(e) {
    for (const [t, i] of this._accounts.entries()) {
      const o = i.getAddresses();
      for (const a of o)
        if (a.address == e) return a;
    }
    return null;
  }
  /**
   * Imports an existing account into the store
   * @param accountData The account data to import
   * @throws Error if an account with the same key already exists
   */
  importAccount(e) {
    let t = e.getAccountStoreKey();
    if (this._accounts.get(t)) throw Error("Account already exists!");
    this._accounts.set(String(t), e);
  }
  /**
   * Exports account data by index
   * @param accountIndex The account index to export
   * @returns The account data
   * @throws Error if the account doesn't exist
   */
  exportAccount(e) {
    if (!this._accounts.get(e)) throw Error("Cannot find account!");
    return this._accounts.get(e);
  }
  /**
   * Removes an account from the store
   * @param accountIndex The account index to remove
   * @throws Error if the account doesn't exist
   */
  removeAccount(e) {
    if (!this._accounts.get(e)) throw Error("Cannot find account!");
    this._accounts.delete(e);
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
  getAccount(e) {
    return this._accounts.get(e);
  }
  /**
   * Retrieves all accounts of a specific type
   * @param accountType The type of accounts to retrieve
   * @returns Array of accounts matching the specified type
   */
  getAccountsByType(e) {
    const t = [];
    for (const [i, o] of this._accounts)
      switch (e) {
        case Jt.DAPP_ACCOUNT:
          i.startsWith("2.") && t.push(o);
          break;
        case Jt.VAULT_ACCOUNT:
          i.startsWith("1.") && t.push(o);
          break;
        case Jt.NEXA_ACCOUNT:
          i.includes(".") || t.push(o);
          break;
      }
    return t;
  }
}
class yt {
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
  static validateState(e, t) {
    if (!e) throw new Error(`Invalid State: ${t}`);
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
  static validateArgument(e, t, i = "") {
    if (!e) throw new Error(`Invalid Argument: ${t}. ${i}`);
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
  static validateArgumentType(e, t, i) {
    if (i = i || "(unknown name)", te(t)) {
      if (t === "Buffer") {
        if (!Buffer.isBuffer(e)) throw new TypeError(`Invalid Argument for ${i}, expected ${t} but got ${typeof e}`);
      } else if (typeof e !== t) throw new TypeError(`Invalid Argument for ${i}, expected ${t} but got ${typeof e}`);
    } else if (!(e instanceof t)) throw new TypeError(`Invalid Argument for ${i}, expected ${t} but got ${typeof e}`);
  }
}
class Ei {
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
  constructor(e, t) {
    if (this._network = Rt.get(t) ?? Rt.mainnet, this._accountStore = new kd(), ze(e)) {
      this.phrase = Vr.generateMnemonic(128, void 0, Vr.wordlists.english);
      const i = Vr.mnemonicToSeedSync(this.phrase, ""), o = wt.fromSeed(i, this._network ?? Rt.mainnet);
      this.masterKey = o.deriveChild(44, !0).deriveChild(29223, !0);
    } else if (e instanceof wt)
      this.masterKey = e.deriveChild(44, !0).deriveChild(29223, !0);
    else if (te(e)) {
      yt.validateArgument(Vr.validateMnemonic(e), "Invalid BIP39 seed phrase provided"), this.phrase = e;
      const i = Vr.mnemonicToSeedSync(this.phrase, ""), o = wt.fromSeed(i, this._network ?? Rt.mainnet);
      this.masterKey = o.deriveChild(44, !0).deriveChild(29223, !0);
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
    return new Ei();
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
  static fromSeedPhrase(e, t) {
    return yt.validateArgument(te(e), "seedphrase must be provided"), yt.validateArgument(Vr.validateMnemonic(e), "Invalid BIP39 seed phrase provided"), new Ei(e, t);
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
  static fromXpriv(e, t) {
    yt.validateArgument(te(e), "private key must be provided"), yt.validateArgument(e.trim().length > 0, "private key cannot be empty");
    let i;
    try {
      i = wt.fromString(e);
    } catch (o) {
      throw new Error(`Invalid extended private key format: ${o instanceof Error ? o.message : "Unknown error"}`);
    }
    return new Ei(i, t);
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
    const e = await cd(this.masterKey);
    for (const t of e) this._accountStore.importAccount(t);
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
  newTransaction(e, t) {
    let i;
    return t instanceof Jr ? i = new Ai(e, t) : te(t) ? i = new Ai(e).parseTxHex(t) : gs(t) && !ze(t) ? i = new Ai(e).parseTxBuffer(t) : i = new Ai(e), i.onNetwork(this._network);
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
  async newAccount(e) {
    return await this.accountStore.createAccount(e, this.masterKey);
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
  async sendTransaction(e) {
    return yt.validateArgument(te(e), "transaction must be present and valid"), zt.broadcast(e);
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
  async subscribeToAddressNotifications(e, t) {
    yt.validateArgument(!ze(e), "addresses parameter is required"), yt.validateArgument(!ze(t), "callback function is required");
    let i;
    if (te(e)) i = [
      e
    ];
    else if (rr(e))
      yt.validateArgument(e.length > 0, "addresses array cannot be empty"), i = e;
    else throw new Error("addresses must be a string or array of strings");
    return zt.subscribeToAddresses(i, t);
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
  async unsubscribeFromAddressNotifications(e, t) {
    yt.validateArgument(!ze(e), "addresses parameter is required"), yt.validateArgument(!ze(t), "callback function is required");
    let i;
    if (te(e)) i = [
      e
    ];
    else if (rr(e))
      yt.validateArgument(e.length > 0, "addresses array cannot be empty"), i = e;
    else throw new Error("addresses must be a string or array of strings");
    return zt.unsubscribeFromAddresses(i, t);
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
  signMessage(e, t) {
    let i = new tr(e);
    const o = this.accountStore.findKeyForAddress(t);
    return yt.validateArgument(!ze(o), "You dont own this private key"), i.sign(o?.key.privateKey);
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
  verifyMessage(e, t, i) {
    yt.validateArgument(!ze(e), "message is required"), yt.validateArgument(!ze(t), "signature is required"), yt.validateArgument(!ze(i), "address is required ");
    let o = new tr(e);
    const a = this.accountStore.findKeyForAddress(i);
    return yt.validateArgument(!ze(a), "You dont own this private key"), o.verify(i, t);
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
}
function Sd(r) {
  if (r !== void 0) {
    let e = "More than one instance of Wallet SDKPlease make sure to require Wallet SDK and check that submodules do not also include their own Wallet SDK dependency.";
    throw new Error(e);
  }
}
Sd($s._walletSdk_ver);
$s._walletSdk_ver = `v${xn.version}`;
`${xn.version}`;
var Ea = {}, ri = {}, as;
function Ad() {
  if (as) return ri;
  as = 1, ri.byteLength = c, ri.toByteArray = h, ri.fromByteArray = M;
  for (var r = [], e = [], t = typeof Uint8Array < "u" ? Uint8Array : Array, i = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", o = 0, a = i.length; o < a; ++o)
    r[o] = i[o], e[i.charCodeAt(o)] = o;
  e[45] = 62, e[95] = 63;
  function p(I) {
    var _ = I.length;
    if (_ % 4 > 0)
      throw new Error("Invalid string. Length must be a multiple of 4");
    var E = I.indexOf("=");
    E === -1 && (E = _);
    var O = E === _ ? 0 : 4 - E % 4;
    return [E, O];
  }
  function c(I) {
    var _ = p(I), E = _[0], O = _[1];
    return (E + O) * 3 / 4 - O;
  }
  function g(I, _, E) {
    return (_ + E) * 3 / 4 - E;
  }
  function h(I) {
    var _, E = p(I), O = E[0], N = E[1], U = new t(g(I, O, N)), j = 0, F = N > 0 ? O - 4 : O, C;
    for (C = 0; C < F; C += 4)
      _ = e[I.charCodeAt(C)] << 18 | e[I.charCodeAt(C + 1)] << 12 | e[I.charCodeAt(C + 2)] << 6 | e[I.charCodeAt(C + 3)], U[j++] = _ >> 16 & 255, U[j++] = _ >> 8 & 255, U[j++] = _ & 255;
    return N === 2 && (_ = e[I.charCodeAt(C)] << 2 | e[I.charCodeAt(C + 1)] >> 4, U[j++] = _ & 255), N === 1 && (_ = e[I.charCodeAt(C)] << 10 | e[I.charCodeAt(C + 1)] << 4 | e[I.charCodeAt(C + 2)] >> 2, U[j++] = _ >> 8 & 255, U[j++] = _ & 255), U;
  }
  function m(I) {
    return r[I >> 18 & 63] + r[I >> 12 & 63] + r[I >> 6 & 63] + r[I & 63];
  }
  function S(I, _, E) {
    for (var O, N = [], U = _; U < E; U += 3)
      O = (I[U] << 16 & 16711680) + (I[U + 1] << 8 & 65280) + (I[U + 2] & 255), N.push(m(O));
    return N.join("");
  }
  function M(I) {
    for (var _, E = I.length, O = E % 3, N = [], U = 16383, j = 0, F = E - O; j < F; j += U)
      N.push(S(I, j, j + U > F ? F : j + U));
    return O === 1 ? (_ = I[E - 1], N.push(
      r[_ >> 2] + r[_ << 4 & 63] + "=="
    )) : O === 2 && (_ = (I[E - 2] << 8) + I[E - 1], N.push(
      r[_ >> 10] + r[_ >> 4 & 63] + r[_ << 2 & 63] + "="
    )), N.join("");
  }
  return ri;
}
var _i = {};
/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
var ns;
function _d() {
  return ns || (ns = 1, _i.read = function(r, e, t, i, o) {
    var a, p, c = o * 8 - i - 1, g = (1 << c) - 1, h = g >> 1, m = -7, S = t ? o - 1 : 0, M = t ? -1 : 1, I = r[e + S];
    for (S += M, a = I & (1 << -m) - 1, I >>= -m, m += c; m > 0; a = a * 256 + r[e + S], S += M, m -= 8)
      ;
    for (p = a & (1 << -m) - 1, a >>= -m, m += i; m > 0; p = p * 256 + r[e + S], S += M, m -= 8)
      ;
    if (a === 0)
      a = 1 - h;
    else {
      if (a === g)
        return p ? NaN : (I ? -1 : 1) * (1 / 0);
      p = p + Math.pow(2, i), a = a - h;
    }
    return (I ? -1 : 1) * p * Math.pow(2, a - i);
  }, _i.write = function(r, e, t, i, o, a) {
    var p, c, g, h = a * 8 - o - 1, m = (1 << h) - 1, S = m >> 1, M = o === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0, I = i ? 0 : a - 1, _ = i ? 1 : -1, E = e < 0 || e === 0 && 1 / e < 0 ? 1 : 0;
    for (e = Math.abs(e), isNaN(e) || e === 1 / 0 ? (c = isNaN(e) ? 1 : 0, p = m) : (p = Math.floor(Math.log(e) / Math.LN2), e * (g = Math.pow(2, -p)) < 1 && (p--, g *= 2), p + S >= 1 ? e += M / g : e += M * Math.pow(2, 1 - S), e * g >= 2 && (p++, g /= 2), p + S >= m ? (c = 0, p = m) : p + S >= 1 ? (c = (e * g - 1) * Math.pow(2, o), p = p + S) : (c = e * Math.pow(2, S - 1) * Math.pow(2, o), p = 0)); o >= 8; r[t + I] = c & 255, I += _, c /= 256, o -= 8)
      ;
    for (p = p << o | c, h += o; h > 0; r[t + I] = p & 255, I += _, p /= 256, h -= 8)
      ;
    r[t + I - _] |= E * 128;
  }), _i;
}
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
var os;
function Md() {
  return os || (os = 1, (function(r) {
    const e = Ad(), t = _d(), i = typeof Symbol == "function" && typeof Symbol.for == "function" ? Symbol.for("nodejs.util.inspect.custom") : null;
    r.Buffer = c, r.SlowBuffer = U, r.INSPECT_MAX_BYTES = 50;
    const o = 2147483647;
    r.kMaxLength = o, c.TYPED_ARRAY_SUPPORT = a(), !c.TYPED_ARRAY_SUPPORT && typeof console < "u" && typeof console.error == "function" && console.error(
      "This browser lacks typed array (Uint8Array) support which is required by `buffer` v5.x. Use `buffer` v4.x if you require old browser support."
    );
    function a() {
      try {
        const B = new Uint8Array(1), b = { foo: function() {
          return 42;
        } };
        return Object.setPrototypeOf(b, Uint8Array.prototype), Object.setPrototypeOf(B, b), B.foo() === 42;
      } catch {
        return !1;
      }
    }
    Object.defineProperty(c.prototype, "parent", {
      enumerable: !0,
      get: function() {
        if (c.isBuffer(this))
          return this.buffer;
      }
    }), Object.defineProperty(c.prototype, "offset", {
      enumerable: !0,
      get: function() {
        if (c.isBuffer(this))
          return this.byteOffset;
      }
    });
    function p(B) {
      if (B > o)
        throw new RangeError('The value "' + B + '" is invalid for option "size"');
      const b = new Uint8Array(B);
      return Object.setPrototypeOf(b, c.prototype), b;
    }
    function c(B, b, x) {
      if (typeof B == "number") {
        if (typeof b == "string")
          throw new TypeError(
            'The "string" argument must be of type string. Received type number'
          );
        return S(B);
      }
      return g(B, b, x);
    }
    c.poolSize = 8192;
    function g(B, b, x) {
      if (typeof B == "string")
        return M(B, b);
      if (ArrayBuffer.isView(B))
        return _(B);
      if (B == null)
        throw new TypeError(
          "The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof B
        );
      if (Pe(B, ArrayBuffer) || B && Pe(B.buffer, ArrayBuffer) || typeof SharedArrayBuffer < "u" && (Pe(B, SharedArrayBuffer) || B && Pe(B.buffer, SharedArrayBuffer)))
        return E(B, b, x);
      if (typeof B == "number")
        throw new TypeError(
          'The "value" argument must not be of type number. Received type number'
        );
      const T = B.valueOf && B.valueOf();
      if (T != null && T !== B)
        return c.from(T, b, x);
      const L = O(B);
      if (L) return L;
      if (typeof Symbol < "u" && Symbol.toPrimitive != null && typeof B[Symbol.toPrimitive] == "function")
        return c.from(B[Symbol.toPrimitive]("string"), b, x);
      throw new TypeError(
        "The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof B
      );
    }
    c.from = function(B, b, x) {
      return g(B, b, x);
    }, Object.setPrototypeOf(c.prototype, Uint8Array.prototype), Object.setPrototypeOf(c, Uint8Array);
    function h(B) {
      if (typeof B != "number")
        throw new TypeError('"size" argument must be of type number');
      if (B < 0)
        throw new RangeError('The value "' + B + '" is invalid for option "size"');
    }
    function m(B, b, x) {
      return h(B), B <= 0 ? p(B) : b !== void 0 ? typeof x == "string" ? p(B).fill(b, x) : p(B).fill(b) : p(B);
    }
    c.alloc = function(B, b, x) {
      return m(B, b, x);
    };
    function S(B) {
      return h(B), p(B < 0 ? 0 : N(B) | 0);
    }
    c.allocUnsafe = function(B) {
      return S(B);
    }, c.allocUnsafeSlow = function(B) {
      return S(B);
    };
    function M(B, b) {
      if ((typeof b != "string" || b === "") && (b = "utf8"), !c.isEncoding(b))
        throw new TypeError("Unknown encoding: " + b);
      const x = j(B, b) | 0;
      let T = p(x);
      const L = T.write(B, b);
      return L !== x && (T = T.slice(0, L)), T;
    }
    function I(B) {
      const b = B.length < 0 ? 0 : N(B.length) | 0, x = p(b);
      for (let T = 0; T < b; T += 1)
        x[T] = B[T] & 255;
      return x;
    }
    function _(B) {
      if (Pe(B, Uint8Array)) {
        const b = new Uint8Array(B);
        return E(b.buffer, b.byteOffset, b.byteLength);
      }
      return I(B);
    }
    function E(B, b, x) {
      if (b < 0 || B.byteLength < b)
        throw new RangeError('"offset" is outside of buffer bounds');
      if (B.byteLength < b + (x || 0))
        throw new RangeError('"length" is outside of buffer bounds');
      let T;
      return b === void 0 && x === void 0 ? T = new Uint8Array(B) : x === void 0 ? T = new Uint8Array(B, b) : T = new Uint8Array(B, b, x), Object.setPrototypeOf(T, c.prototype), T;
    }
    function O(B) {
      if (c.isBuffer(B)) {
        const b = N(B.length) | 0, x = p(b);
        return x.length === 0 || B.copy(x, 0, 0, b), x;
      }
      if (B.length !== void 0)
        return typeof B.length != "number" || je(B.length) ? p(0) : I(B);
      if (B.type === "Buffer" && Array.isArray(B.data))
        return I(B.data);
    }
    function N(B) {
      if (B >= o)
        throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x" + o.toString(16) + " bytes");
      return B | 0;
    }
    function U(B) {
      return +B != B && (B = 0), c.alloc(+B);
    }
    c.isBuffer = function(b) {
      return b != null && b._isBuffer === !0 && b !== c.prototype;
    }, c.compare = function(b, x) {
      if (Pe(b, Uint8Array) && (b = c.from(b, b.offset, b.byteLength)), Pe(x, Uint8Array) && (x = c.from(x, x.offset, x.byteLength)), !c.isBuffer(b) || !c.isBuffer(x))
        throw new TypeError(
          'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
        );
      if (b === x) return 0;
      let T = b.length, L = x.length;
      for (let D = 0, H = Math.min(T, L); D < H; ++D)
        if (b[D] !== x[D]) {
          T = b[D], L = x[D];
          break;
        }
      return T < L ? -1 : L < T ? 1 : 0;
    }, c.isEncoding = function(b) {
      switch (String(b).toLowerCase()) {
        case "hex":
        case "utf8":
        case "utf-8":
        case "ascii":
        case "latin1":
        case "binary":
        case "base64":
        case "ucs2":
        case "ucs-2":
        case "utf16le":
        case "utf-16le":
          return !0;
        default:
          return !1;
      }
    }, c.concat = function(b, x) {
      if (!Array.isArray(b))
        throw new TypeError('"list" argument must be an Array of Buffers');
      if (b.length === 0)
        return c.alloc(0);
      let T;
      if (x === void 0)
        for (x = 0, T = 0; T < b.length; ++T)
          x += b[T].length;
      const L = c.allocUnsafe(x);
      let D = 0;
      for (T = 0; T < b.length; ++T) {
        let H = b[T];
        if (Pe(H, Uint8Array))
          D + H.length > L.length ? (c.isBuffer(H) || (H = c.from(H)), H.copy(L, D)) : Uint8Array.prototype.set.call(
            L,
            H,
            D
          );
        else if (c.isBuffer(H))
          H.copy(L, D);
        else
          throw new TypeError('"list" argument must be an Array of Buffers');
        D += H.length;
      }
      return L;
    };
    function j(B, b) {
      if (c.isBuffer(B))
        return B.length;
      if (ArrayBuffer.isView(B) || Pe(B, ArrayBuffer))
        return B.byteLength;
      if (typeof B != "string")
        throw new TypeError(
          'The "string" argument must be one of type string, Buffer, or ArrayBuffer. Received type ' + typeof B
        );
      const x = B.length, T = arguments.length > 2 && arguments[2] === !0;
      if (!T && x === 0) return 0;
      let L = !1;
      for (; ; )
        switch (b) {
          case "ascii":
          case "latin1":
          case "binary":
            return x;
          case "utf8":
          case "utf-8":
            return Fe(B).length;
          case "ucs2":
          case "ucs-2":
          case "utf16le":
          case "utf-16le":
            return x * 2;
          case "hex":
            return x >>> 1;
          case "base64":
            return De(B).length;
          default:
            if (L)
              return T ? -1 : Fe(B).length;
            b = ("" + b).toLowerCase(), L = !0;
        }
    }
    c.byteLength = j;
    function F(B, b, x) {
      let T = !1;
      if ((b === void 0 || b < 0) && (b = 0), b > this.length || ((x === void 0 || x > this.length) && (x = this.length), x <= 0) || (x >>>= 0, b >>>= 0, x <= b))
        return "";
      for (B || (B = "utf8"); ; )
        switch (B) {
          case "hex":
            return k(this, b, x);
          case "utf8":
          case "utf-8":
            return n(this, b, x);
          case "ascii":
            return w(this, b, x);
          case "latin1":
          case "binary":
            return A(this, b, x);
          case "base64":
            return u(this, b, x);
          case "ucs2":
          case "ucs-2":
          case "utf16le":
          case "utf-16le":
            return l(this, b, x);
          default:
            if (T) throw new TypeError("Unknown encoding: " + B);
            B = (B + "").toLowerCase(), T = !0;
        }
    }
    c.prototype._isBuffer = !0;
    function C(B, b, x) {
      const T = B[b];
      B[b] = B[x], B[x] = T;
    }
    c.prototype.swap16 = function() {
      const b = this.length;
      if (b % 2 !== 0)
        throw new RangeError("Buffer size must be a multiple of 16-bits");
      for (let x = 0; x < b; x += 2)
        C(this, x, x + 1);
      return this;
    }, c.prototype.swap32 = function() {
      const b = this.length;
      if (b % 4 !== 0)
        throw new RangeError("Buffer size must be a multiple of 32-bits");
      for (let x = 0; x < b; x += 4)
        C(this, x, x + 3), C(this, x + 1, x + 2);
      return this;
    }, c.prototype.swap64 = function() {
      const b = this.length;
      if (b % 8 !== 0)
        throw new RangeError("Buffer size must be a multiple of 64-bits");
      for (let x = 0; x < b; x += 8)
        C(this, x, x + 7), C(this, x + 1, x + 6), C(this, x + 2, x + 5), C(this, x + 3, x + 4);
      return this;
    }, c.prototype.toString = function() {
      const b = this.length;
      return b === 0 ? "" : arguments.length === 0 ? n(this, 0, b) : F.apply(this, arguments);
    }, c.prototype.toLocaleString = c.prototype.toString, c.prototype.equals = function(b) {
      if (!c.isBuffer(b)) throw new TypeError("Argument must be a Buffer");
      return this === b ? !0 : c.compare(this, b) === 0;
    }, c.prototype.inspect = function() {
      let b = "";
      const x = r.INSPECT_MAX_BYTES;
      return b = this.toString("hex", 0, x).replace(/(.{2})/g, "$1 ").trim(), this.length > x && (b += " ... "), "<Buffer " + b + ">";
    }, i && (c.prototype[i] = c.prototype.inspect), c.prototype.compare = function(b, x, T, L, D) {
      if (Pe(b, Uint8Array) && (b = c.from(b, b.offset, b.byteLength)), !c.isBuffer(b))
        throw new TypeError(
          'The "target" argument must be one of type Buffer or Uint8Array. Received type ' + typeof b
        );
      if (x === void 0 && (x = 0), T === void 0 && (T = b ? b.length : 0), L === void 0 && (L = 0), D === void 0 && (D = this.length), x < 0 || T > b.length || L < 0 || D > this.length)
        throw new RangeError("out of range index");
      if (L >= D && x >= T)
        return 0;
      if (L >= D)
        return -1;
      if (x >= T)
        return 1;
      if (x >>>= 0, T >>>= 0, L >>>= 0, D >>>= 0, this === b) return 0;
      let H = D - L, ae = T - x;
      const be = Math.min(H, ae), ie = this.slice(L, D), ve = b.slice(x, T);
      for (let ue = 0; ue < be; ++ue)
        if (ie[ue] !== ve[ue]) {
          H = ie[ue], ae = ve[ue];
          break;
        }
      return H < ae ? -1 : ae < H ? 1 : 0;
    };
    function q(B, b, x, T, L) {
      if (B.length === 0) return -1;
      if (typeof x == "string" ? (T = x, x = 0) : x > 2147483647 ? x = 2147483647 : x < -2147483648 && (x = -2147483648), x = +x, je(x) && (x = L ? 0 : B.length - 1), x < 0 && (x = B.length + x), x >= B.length) {
        if (L) return -1;
        x = B.length - 1;
      } else if (x < 0)
        if (L) x = 0;
        else return -1;
      if (typeof b == "string" && (b = c.from(b, T)), c.isBuffer(b))
        return b.length === 0 ? -1 : V(B, b, x, T, L);
      if (typeof b == "number")
        return b = b & 255, typeof Uint8Array.prototype.indexOf == "function" ? L ? Uint8Array.prototype.indexOf.call(B, b, x) : Uint8Array.prototype.lastIndexOf.call(B, b, x) : V(B, [b], x, T, L);
      throw new TypeError("val must be string, number or Buffer");
    }
    function V(B, b, x, T, L) {
      let D = 1, H = B.length, ae = b.length;
      if (T !== void 0 && (T = String(T).toLowerCase(), T === "ucs2" || T === "ucs-2" || T === "utf16le" || T === "utf-16le")) {
        if (B.length < 2 || b.length < 2)
          return -1;
        D = 2, H /= 2, ae /= 2, x /= 2;
      }
      function be(ve, ue) {
        return D === 1 ? ve[ue] : ve.readUInt16BE(ue * D);
      }
      let ie;
      if (L) {
        let ve = -1;
        for (ie = x; ie < H; ie++)
          if (be(B, ie) === be(b, ve === -1 ? 0 : ie - ve)) {
            if (ve === -1 && (ve = ie), ie - ve + 1 === ae) return ve * D;
          } else
            ve !== -1 && (ie -= ie - ve), ve = -1;
      } else
        for (x + ae > H && (x = H - ae), ie = x; ie >= 0; ie--) {
          let ve = !0;
          for (let ue = 0; ue < ae; ue++)
            if (be(B, ie + ue) !== be(b, ue)) {
              ve = !1;
              break;
            }
          if (ve) return ie;
        }
      return -1;
    }
    c.prototype.includes = function(b, x, T) {
      return this.indexOf(b, x, T) !== -1;
    }, c.prototype.indexOf = function(b, x, T) {
      return q(this, b, x, T, !0);
    }, c.prototype.lastIndexOf = function(b, x, T) {
      return q(this, b, x, T, !1);
    };
    function Z(B, b, x, T) {
      x = Number(x) || 0;
      const L = B.length - x;
      T ? (T = Number(T), T > L && (T = L)) : T = L;
      const D = b.length;
      T > D / 2 && (T = D / 2);
      let H;
      for (H = 0; H < T; ++H) {
        const ae = parseInt(b.substr(H * 2, 2), 16);
        if (je(ae)) return H;
        B[x + H] = ae;
      }
      return H;
    }
    function K(B, b, x, T) {
      return ce(Fe(b, B.length - x), B, x, T);
    }
    function G(B, b, x, T) {
      return ce(me(b), B, x, T);
    }
    function z(B, b, x, T) {
      return ce(De(b), B, x, T);
    }
    function f(B, b, x, T) {
      return ce(He(b, B.length - x), B, x, T);
    }
    c.prototype.write = function(b, x, T, L) {
      if (x === void 0)
        L = "utf8", T = this.length, x = 0;
      else if (T === void 0 && typeof x == "string")
        L = x, T = this.length, x = 0;
      else if (isFinite(x))
        x = x >>> 0, isFinite(T) ? (T = T >>> 0, L === void 0 && (L = "utf8")) : (L = T, T = void 0);
      else
        throw new Error(
          "Buffer.write(string, encoding, offset[, length]) is no longer supported"
        );
      const D = this.length - x;
      if ((T === void 0 || T > D) && (T = D), b.length > 0 && (T < 0 || x < 0) || x > this.length)
        throw new RangeError("Attempt to write outside buffer bounds");
      L || (L = "utf8");
      let H = !1;
      for (; ; )
        switch (L) {
          case "hex":
            return Z(this, b, x, T);
          case "utf8":
          case "utf-8":
            return K(this, b, x, T);
          case "ascii":
          case "latin1":
          case "binary":
            return G(this, b, x, T);
          case "base64":
            return z(this, b, x, T);
          case "ucs2":
          case "ucs-2":
          case "utf16le":
          case "utf-16le":
            return f(this, b, x, T);
          default:
            if (H) throw new TypeError("Unknown encoding: " + L);
            L = ("" + L).toLowerCase(), H = !0;
        }
    }, c.prototype.toJSON = function() {
      return {
        type: "Buffer",
        data: Array.prototype.slice.call(this._arr || this, 0)
      };
    };
    function u(B, b, x) {
      return b === 0 && x === B.length ? e.fromByteArray(B) : e.fromByteArray(B.slice(b, x));
    }
    function n(B, b, x) {
      x = Math.min(B.length, x);
      const T = [];
      let L = b;
      for (; L < x; ) {
        const D = B[L];
        let H = null, ae = D > 239 ? 4 : D > 223 ? 3 : D > 191 ? 2 : 1;
        if (L + ae <= x) {
          let be, ie, ve, ue;
          switch (ae) {
            case 1:
              D < 128 && (H = D);
              break;
            case 2:
              be = B[L + 1], (be & 192) === 128 && (ue = (D & 31) << 6 | be & 63, ue > 127 && (H = ue));
              break;
            case 3:
              be = B[L + 1], ie = B[L + 2], (be & 192) === 128 && (ie & 192) === 128 && (ue = (D & 15) << 12 | (be & 63) << 6 | ie & 63, ue > 2047 && (ue < 55296 || ue > 57343) && (H = ue));
              break;
            case 4:
              be = B[L + 1], ie = B[L + 2], ve = B[L + 3], (be & 192) === 128 && (ie & 192) === 128 && (ve & 192) === 128 && (ue = (D & 15) << 18 | (be & 63) << 12 | (ie & 63) << 6 | ve & 63, ue > 65535 && ue < 1114112 && (H = ue));
          }
        }
        H === null ? (H = 65533, ae = 1) : H > 65535 && (H -= 65536, T.push(H >>> 10 & 1023 | 55296), H = 56320 | H & 1023), T.push(H), L += ae;
      }
      return d(T);
    }
    const s = 4096;
    function d(B) {
      const b = B.length;
      if (b <= s)
        return String.fromCharCode.apply(String, B);
      let x = "", T = 0;
      for (; T < b; )
        x += String.fromCharCode.apply(
          String,
          B.slice(T, T += s)
        );
      return x;
    }
    function w(B, b, x) {
      let T = "";
      x = Math.min(B.length, x);
      for (let L = b; L < x; ++L)
        T += String.fromCharCode(B[L] & 127);
      return T;
    }
    function A(B, b, x) {
      let T = "";
      x = Math.min(B.length, x);
      for (let L = b; L < x; ++L)
        T += String.fromCharCode(B[L]);
      return T;
    }
    function k(B, b, x) {
      const T = B.length;
      (!b || b < 0) && (b = 0), (!x || x < 0 || x > T) && (x = T);
      let L = "";
      for (let D = b; D < x; ++D)
        L += de[B[D]];
      return L;
    }
    function l(B, b, x) {
      const T = B.slice(b, x);
      let L = "";
      for (let D = 0; D < T.length - 1; D += 2)
        L += String.fromCharCode(T[D] + T[D + 1] * 256);
      return L;
    }
    c.prototype.slice = function(b, x) {
      const T = this.length;
      b = ~~b, x = x === void 0 ? T : ~~x, b < 0 ? (b += T, b < 0 && (b = 0)) : b > T && (b = T), x < 0 ? (x += T, x < 0 && (x = 0)) : x > T && (x = T), x < b && (x = b);
      const L = this.subarray(b, x);
      return Object.setPrototypeOf(L, c.prototype), L;
    };
    function y(B, b, x) {
      if (B % 1 !== 0 || B < 0) throw new RangeError("offset is not uint");
      if (B + b > x) throw new RangeError("Trying to access beyond buffer length");
    }
    c.prototype.readUintLE = c.prototype.readUIntLE = function(b, x, T) {
      b = b >>> 0, x = x >>> 0, T || y(b, x, this.length);
      let L = this[b], D = 1, H = 0;
      for (; ++H < x && (D *= 256); )
        L += this[b + H] * D;
      return L;
    }, c.prototype.readUintBE = c.prototype.readUIntBE = function(b, x, T) {
      b = b >>> 0, x = x >>> 0, T || y(b, x, this.length);
      let L = this[b + --x], D = 1;
      for (; x > 0 && (D *= 256); )
        L += this[b + --x] * D;
      return L;
    }, c.prototype.readUint8 = c.prototype.readUInt8 = function(b, x) {
      return b = b >>> 0, x || y(b, 1, this.length), this[b];
    }, c.prototype.readUint16LE = c.prototype.readUInt16LE = function(b, x) {
      return b = b >>> 0, x || y(b, 2, this.length), this[b] | this[b + 1] << 8;
    }, c.prototype.readUint16BE = c.prototype.readUInt16BE = function(b, x) {
      return b = b >>> 0, x || y(b, 2, this.length), this[b] << 8 | this[b + 1];
    }, c.prototype.readUint32LE = c.prototype.readUInt32LE = function(b, x) {
      return b = b >>> 0, x || y(b, 4, this.length), (this[b] | this[b + 1] << 8 | this[b + 2] << 16) + this[b + 3] * 16777216;
    }, c.prototype.readUint32BE = c.prototype.readUInt32BE = function(b, x) {
      return b = b >>> 0, x || y(b, 4, this.length), this[b] * 16777216 + (this[b + 1] << 16 | this[b + 2] << 8 | this[b + 3]);
    }, c.prototype.readBigUInt64LE = Te(function(b) {
      b = b >>> 0, Ee(b, "offset");
      const x = this[b], T = this[b + 7];
      (x === void 0 || T === void 0) && Ce(b, this.length - 8);
      const L = x + this[++b] * 2 ** 8 + this[++b] * 2 ** 16 + this[++b] * 2 ** 24, D = this[++b] + this[++b] * 2 ** 8 + this[++b] * 2 ** 16 + T * 2 ** 24;
      return BigInt(L) + (BigInt(D) << BigInt(32));
    }), c.prototype.readBigUInt64BE = Te(function(b) {
      b = b >>> 0, Ee(b, "offset");
      const x = this[b], T = this[b + 7];
      (x === void 0 || T === void 0) && Ce(b, this.length - 8);
      const L = x * 2 ** 24 + this[++b] * 2 ** 16 + this[++b] * 2 ** 8 + this[++b], D = this[++b] * 2 ** 24 + this[++b] * 2 ** 16 + this[++b] * 2 ** 8 + T;
      return (BigInt(L) << BigInt(32)) + BigInt(D);
    }), c.prototype.readIntLE = function(b, x, T) {
      b = b >>> 0, x = x >>> 0, T || y(b, x, this.length);
      let L = this[b], D = 1, H = 0;
      for (; ++H < x && (D *= 256); )
        L += this[b + H] * D;
      return D *= 128, L >= D && (L -= Math.pow(2, 8 * x)), L;
    }, c.prototype.readIntBE = function(b, x, T) {
      b = b >>> 0, x = x >>> 0, T || y(b, x, this.length);
      let L = x, D = 1, H = this[b + --L];
      for (; L > 0 && (D *= 256); )
        H += this[b + --L] * D;
      return D *= 128, H >= D && (H -= Math.pow(2, 8 * x)), H;
    }, c.prototype.readInt8 = function(b, x) {
      return b = b >>> 0, x || y(b, 1, this.length), this[b] & 128 ? (255 - this[b] + 1) * -1 : this[b];
    }, c.prototype.readInt16LE = function(b, x) {
      b = b >>> 0, x || y(b, 2, this.length);
      const T = this[b] | this[b + 1] << 8;
      return T & 32768 ? T | 4294901760 : T;
    }, c.prototype.readInt16BE = function(b, x) {
      b = b >>> 0, x || y(b, 2, this.length);
      const T = this[b + 1] | this[b] << 8;
      return T & 32768 ? T | 4294901760 : T;
    }, c.prototype.readInt32LE = function(b, x) {
      return b = b >>> 0, x || y(b, 4, this.length), this[b] | this[b + 1] << 8 | this[b + 2] << 16 | this[b + 3] << 24;
    }, c.prototype.readInt32BE = function(b, x) {
      return b = b >>> 0, x || y(b, 4, this.length), this[b] << 24 | this[b + 1] << 16 | this[b + 2] << 8 | this[b + 3];
    }, c.prototype.readBigInt64LE = Te(function(b) {
      b = b >>> 0, Ee(b, "offset");
      const x = this[b], T = this[b + 7];
      (x === void 0 || T === void 0) && Ce(b, this.length - 8);
      const L = this[b + 4] + this[b + 5] * 2 ** 8 + this[b + 6] * 2 ** 16 + (T << 24);
      return (BigInt(L) << BigInt(32)) + BigInt(x + this[++b] * 2 ** 8 + this[++b] * 2 ** 16 + this[++b] * 2 ** 24);
    }), c.prototype.readBigInt64BE = Te(function(b) {
      b = b >>> 0, Ee(b, "offset");
      const x = this[b], T = this[b + 7];
      (x === void 0 || T === void 0) && Ce(b, this.length - 8);
      const L = (x << 24) + // Overflow
      this[++b] * 2 ** 16 + this[++b] * 2 ** 8 + this[++b];
      return (BigInt(L) << BigInt(32)) + BigInt(this[++b] * 2 ** 24 + this[++b] * 2 ** 16 + this[++b] * 2 ** 8 + T);
    }), c.prototype.readFloatLE = function(b, x) {
      return b = b >>> 0, x || y(b, 4, this.length), t.read(this, b, !0, 23, 4);
    }, c.prototype.readFloatBE = function(b, x) {
      return b = b >>> 0, x || y(b, 4, this.length), t.read(this, b, !1, 23, 4);
    }, c.prototype.readDoubleLE = function(b, x) {
      return b = b >>> 0, x || y(b, 8, this.length), t.read(this, b, !0, 52, 8);
    }, c.prototype.readDoubleBE = function(b, x) {
      return b = b >>> 0, x || y(b, 8, this.length), t.read(this, b, !1, 52, 8);
    };
    function v(B, b, x, T, L, D) {
      if (!c.isBuffer(B)) throw new TypeError('"buffer" argument must be a Buffer instance');
      if (b > L || b < D) throw new RangeError('"value" argument is out of bounds');
      if (x + T > B.length) throw new RangeError("Index out of range");
    }
    c.prototype.writeUintLE = c.prototype.writeUIntLE = function(b, x, T, L) {
      if (b = +b, x = x >>> 0, T = T >>> 0, !L) {
        const ae = Math.pow(2, 8 * T) - 1;
        v(this, b, x, T, ae, 0);
      }
      let D = 1, H = 0;
      for (this[x] = b & 255; ++H < T && (D *= 256); )
        this[x + H] = b / D & 255;
      return x + T;
    }, c.prototype.writeUintBE = c.prototype.writeUIntBE = function(b, x, T, L) {
      if (b = +b, x = x >>> 0, T = T >>> 0, !L) {
        const ae = Math.pow(2, 8 * T) - 1;
        v(this, b, x, T, ae, 0);
      }
      let D = T - 1, H = 1;
      for (this[x + D] = b & 255; --D >= 0 && (H *= 256); )
        this[x + D] = b / H & 255;
      return x + T;
    }, c.prototype.writeUint8 = c.prototype.writeUInt8 = function(b, x, T) {
      return b = +b, x = x >>> 0, T || v(this, b, x, 1, 255, 0), this[x] = b & 255, x + 1;
    }, c.prototype.writeUint16LE = c.prototype.writeUInt16LE = function(b, x, T) {
      return b = +b, x = x >>> 0, T || v(this, b, x, 2, 65535, 0), this[x] = b & 255, this[x + 1] = b >>> 8, x + 2;
    }, c.prototype.writeUint16BE = c.prototype.writeUInt16BE = function(b, x, T) {
      return b = +b, x = x >>> 0, T || v(this, b, x, 2, 65535, 0), this[x] = b >>> 8, this[x + 1] = b & 255, x + 2;
    }, c.prototype.writeUint32LE = c.prototype.writeUInt32LE = function(b, x, T) {
      return b = +b, x = x >>> 0, T || v(this, b, x, 4, 4294967295, 0), this[x + 3] = b >>> 24, this[x + 2] = b >>> 16, this[x + 1] = b >>> 8, this[x] = b & 255, x + 4;
    }, c.prototype.writeUint32BE = c.prototype.writeUInt32BE = function(b, x, T) {
      return b = +b, x = x >>> 0, T || v(this, b, x, 4, 4294967295, 0), this[x] = b >>> 24, this[x + 1] = b >>> 16, this[x + 2] = b >>> 8, this[x + 3] = b & 255, x + 4;
    };
    function P(B, b, x, T, L) {
      he(b, T, L, B, x, 7);
      let D = Number(b & BigInt(4294967295));
      B[x++] = D, D = D >> 8, B[x++] = D, D = D >> 8, B[x++] = D, D = D >> 8, B[x++] = D;
      let H = Number(b >> BigInt(32) & BigInt(4294967295));
      return B[x++] = H, H = H >> 8, B[x++] = H, H = H >> 8, B[x++] = H, H = H >> 8, B[x++] = H, x;
    }
    function J(B, b, x, T, L) {
      he(b, T, L, B, x, 7);
      let D = Number(b & BigInt(4294967295));
      B[x + 7] = D, D = D >> 8, B[x + 6] = D, D = D >> 8, B[x + 5] = D, D = D >> 8, B[x + 4] = D;
      let H = Number(b >> BigInt(32) & BigInt(4294967295));
      return B[x + 3] = H, H = H >> 8, B[x + 2] = H, H = H >> 8, B[x + 1] = H, H = H >> 8, B[x] = H, x + 8;
    }
    c.prototype.writeBigUInt64LE = Te(function(b, x = 0) {
      return P(this, b, x, BigInt(0), BigInt("0xffffffffffffffff"));
    }), c.prototype.writeBigUInt64BE = Te(function(b, x = 0) {
      return J(this, b, x, BigInt(0), BigInt("0xffffffffffffffff"));
    }), c.prototype.writeIntLE = function(b, x, T, L) {
      if (b = +b, x = x >>> 0, !L) {
        const be = Math.pow(2, 8 * T - 1);
        v(this, b, x, T, be - 1, -be);
      }
      let D = 0, H = 1, ae = 0;
      for (this[x] = b & 255; ++D < T && (H *= 256); )
        b < 0 && ae === 0 && this[x + D - 1] !== 0 && (ae = 1), this[x + D] = (b / H >> 0) - ae & 255;
      return x + T;
    }, c.prototype.writeIntBE = function(b, x, T, L) {
      if (b = +b, x = x >>> 0, !L) {
        const be = Math.pow(2, 8 * T - 1);
        v(this, b, x, T, be - 1, -be);
      }
      let D = T - 1, H = 1, ae = 0;
      for (this[x + D] = b & 255; --D >= 0 && (H *= 256); )
        b < 0 && ae === 0 && this[x + D + 1] !== 0 && (ae = 1), this[x + D] = (b / H >> 0) - ae & 255;
      return x + T;
    }, c.prototype.writeInt8 = function(b, x, T) {
      return b = +b, x = x >>> 0, T || v(this, b, x, 1, 127, -128), b < 0 && (b = 255 + b + 1), this[x] = b & 255, x + 1;
    }, c.prototype.writeInt16LE = function(b, x, T) {
      return b = +b, x = x >>> 0, T || v(this, b, x, 2, 32767, -32768), this[x] = b & 255, this[x + 1] = b >>> 8, x + 2;
    }, c.prototype.writeInt16BE = function(b, x, T) {
      return b = +b, x = x >>> 0, T || v(this, b, x, 2, 32767, -32768), this[x] = b >>> 8, this[x + 1] = b & 255, x + 2;
    }, c.prototype.writeInt32LE = function(b, x, T) {
      return b = +b, x = x >>> 0, T || v(this, b, x, 4, 2147483647, -2147483648), this[x] = b & 255, this[x + 1] = b >>> 8, this[x + 2] = b >>> 16, this[x + 3] = b >>> 24, x + 4;
    }, c.prototype.writeInt32BE = function(b, x, T) {
      return b = +b, x = x >>> 0, T || v(this, b, x, 4, 2147483647, -2147483648), b < 0 && (b = 4294967295 + b + 1), this[x] = b >>> 24, this[x + 1] = b >>> 16, this[x + 2] = b >>> 8, this[x + 3] = b & 255, x + 4;
    }, c.prototype.writeBigInt64LE = Te(function(b, x = 0) {
      return P(this, b, x, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
    }), c.prototype.writeBigInt64BE = Te(function(b, x = 0) {
      return J(this, b, x, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
    });
    function Y(B, b, x, T, L, D) {
      if (x + T > B.length) throw new RangeError("Index out of range");
      if (x < 0) throw new RangeError("Index out of range");
    }
    function Q(B, b, x, T, L) {
      return b = +b, x = x >>> 0, L || Y(B, b, x, 4), t.write(B, b, x, T, 23, 4), x + 4;
    }
    c.prototype.writeFloatLE = function(b, x, T) {
      return Q(this, b, x, !0, T);
    }, c.prototype.writeFloatBE = function(b, x, T) {
      return Q(this, b, x, !1, T);
    };
    function se(B, b, x, T, L) {
      return b = +b, x = x >>> 0, L || Y(B, b, x, 8), t.write(B, b, x, T, 52, 8), x + 8;
    }
    c.prototype.writeDoubleLE = function(b, x, T) {
      return se(this, b, x, !0, T);
    }, c.prototype.writeDoubleBE = function(b, x, T) {
      return se(this, b, x, !1, T);
    }, c.prototype.copy = function(b, x, T, L) {
      if (!c.isBuffer(b)) throw new TypeError("argument should be a Buffer");
      if (T || (T = 0), !L && L !== 0 && (L = this.length), x >= b.length && (x = b.length), x || (x = 0), L > 0 && L < T && (L = T), L === T || b.length === 0 || this.length === 0) return 0;
      if (x < 0)
        throw new RangeError("targetStart out of bounds");
      if (T < 0 || T >= this.length) throw new RangeError("Index out of range");
      if (L < 0) throw new RangeError("sourceEnd out of bounds");
      L > this.length && (L = this.length), b.length - x < L - T && (L = b.length - x + T);
      const D = L - T;
      return this === b && typeof Uint8Array.prototype.copyWithin == "function" ? this.copyWithin(x, T, L) : Uint8Array.prototype.set.call(
        b,
        this.subarray(T, L),
        x
      ), D;
    }, c.prototype.fill = function(b, x, T, L) {
      if (typeof b == "string") {
        if (typeof x == "string" ? (L = x, x = 0, T = this.length) : typeof T == "string" && (L = T, T = this.length), L !== void 0 && typeof L != "string")
          throw new TypeError("encoding must be a string");
        if (typeof L == "string" && !c.isEncoding(L))
          throw new TypeError("Unknown encoding: " + L);
        if (b.length === 1) {
          const H = b.charCodeAt(0);
          (L === "utf8" && H < 128 || L === "latin1") && (b = H);
        }
      } else typeof b == "number" ? b = b & 255 : typeof b == "boolean" && (b = Number(b));
      if (x < 0 || this.length < x || this.length < T)
        throw new RangeError("Out of range index");
      if (T <= x)
        return this;
      x = x >>> 0, T = T === void 0 ? this.length : T >>> 0, b || (b = 0);
      let D;
      if (typeof b == "number")
        for (D = x; D < T; ++D)
          this[D] = b;
      else {
        const H = c.isBuffer(b) ? b : c.from(b, L), ae = H.length;
        if (ae === 0)
          throw new TypeError('The value "' + b + '" is invalid for argument "value"');
        for (D = 0; D < T - x; ++D)
          this[D + x] = H[D % ae];
      }
      return this;
    };
    const pe = {};
    function ne(B, b, x) {
      pe[B] = class extends x {
        constructor() {
          super(), Object.defineProperty(this, "message", {
            value: b.apply(this, arguments),
            writable: !0,
            configurable: !0
          }), this.name = `${this.name} [${B}]`, this.stack, delete this.name;
        }
        get code() {
          return B;
        }
        set code(L) {
          Object.defineProperty(this, "code", {
            configurable: !0,
            enumerable: !0,
            value: L,
            writable: !0
          });
        }
        toString() {
          return `${this.name} [${B}]: ${this.message}`;
        }
      };
    }
    ne(
      "ERR_BUFFER_OUT_OF_BOUNDS",
      function(B) {
        return B ? `${B} is outside of buffer bounds` : "Attempt to access memory outside buffer bounds";
      },
      RangeError
    ), ne(
      "ERR_INVALID_ARG_TYPE",
      function(B, b) {
        return `The "${B}" argument must be of type number. Received type ${typeof b}`;
      },
      TypeError
    ), ne(
      "ERR_OUT_OF_RANGE",
      function(B, b, x) {
        let T = `The value of "${B}" is out of range.`, L = x;
        return Number.isInteger(x) && Math.abs(x) > 2 ** 32 ? L = Ne(String(x)) : typeof x == "bigint" && (L = String(x), (x > BigInt(2) ** BigInt(32) || x < -(BigInt(2) ** BigInt(32))) && (L = Ne(L)), L += "n"), T += ` It must be ${b}. Received ${L}`, T;
      },
      RangeError
    );
    function Ne(B) {
      let b = "", x = B.length;
      const T = B[0] === "-" ? 1 : 0;
      for (; x >= T + 4; x -= 3)
        b = `_${B.slice(x - 3, x)}${b}`;
      return `${B.slice(0, x)}${b}`;
    }
    function qe(B, b, x) {
      Ee(b, "offset"), (B[b] === void 0 || B[b + x] === void 0) && Ce(b, B.length - (x + 1));
    }
    function he(B, b, x, T, L, D) {
      if (B > x || B < b) {
        const H = typeof b == "bigint" ? "n" : "";
        let ae;
        throw b === 0 || b === BigInt(0) ? ae = `>= 0${H} and < 2${H} ** ${(D + 1) * 8}${H}` : ae = `>= -(2${H} ** ${(D + 1) * 8 - 1}${H}) and < 2 ** ${(D + 1) * 8 - 1}${H}`, new pe.ERR_OUT_OF_RANGE("value", ae, B);
      }
      qe(T, L, D);
    }
    function Ee(B, b) {
      if (typeof B != "number")
        throw new pe.ERR_INVALID_ARG_TYPE(b, "number", B);
    }
    function Ce(B, b, x) {
      throw Math.floor(B) !== B ? (Ee(B, x), new pe.ERR_OUT_OF_RANGE("offset", "an integer", B)) : b < 0 ? new pe.ERR_BUFFER_OUT_OF_BOUNDS() : new pe.ERR_OUT_OF_RANGE(
        "offset",
        `>= 0 and <= ${b}`,
        B
      );
    }
    const fe = /[^+/0-9A-Za-z-_]/g;
    function Re(B) {
      if (B = B.split("=")[0], B = B.trim().replace(fe, ""), B.length < 2) return "";
      for (; B.length % 4 !== 0; )
        B = B + "=";
      return B;
    }
    function Fe(B, b) {
      b = b || 1 / 0;
      let x;
      const T = B.length;
      let L = null;
      const D = [];
      for (let H = 0; H < T; ++H) {
        if (x = B.charCodeAt(H), x > 55295 && x < 57344) {
          if (!L) {
            if (x > 56319) {
              (b -= 3) > -1 && D.push(239, 191, 189);
              continue;
            } else if (H + 1 === T) {
              (b -= 3) > -1 && D.push(239, 191, 189);
              continue;
            }
            L = x;
            continue;
          }
          if (x < 56320) {
            (b -= 3) > -1 && D.push(239, 191, 189), L = x;
            continue;
          }
          x = (L - 55296 << 10 | x - 56320) + 65536;
        } else L && (b -= 3) > -1 && D.push(239, 191, 189);
        if (L = null, x < 128) {
          if ((b -= 1) < 0) break;
          D.push(x);
        } else if (x < 2048) {
          if ((b -= 2) < 0) break;
          D.push(
            x >> 6 | 192,
            x & 63 | 128
          );
        } else if (x < 65536) {
          if ((b -= 3) < 0) break;
          D.push(
            x >> 12 | 224,
            x >> 6 & 63 | 128,
            x & 63 | 128
          );
        } else if (x < 1114112) {
          if ((b -= 4) < 0) break;
          D.push(
            x >> 18 | 240,
            x >> 12 & 63 | 128,
            x >> 6 & 63 | 128,
            x & 63 | 128
          );
        } else
          throw new Error("Invalid code point");
      }
      return D;
    }
    function me(B) {
      const b = [];
      for (let x = 0; x < B.length; ++x)
        b.push(B.charCodeAt(x) & 255);
      return b;
    }
    function He(B, b) {
      let x, T, L;
      const D = [];
      for (let H = 0; H < B.length && !((b -= 2) < 0); ++H)
        x = B.charCodeAt(H), T = x >> 8, L = x % 256, D.push(L), D.push(T);
      return D;
    }
    function De(B) {
      return e.toByteArray(Re(B));
    }
    function ce(B, b, x, T) {
      let L;
      for (L = 0; L < T && !(L + x >= b.length || L >= B.length); ++L)
        b[L + x] = B[L];
      return L;
    }
    function Pe(B, b) {
      return B instanceof b || B != null && B.constructor != null && B.constructor.name != null && B.constructor.name === b.name;
    }
    function je(B) {
      return B !== B;
    }
    const de = (function() {
      const B = "0123456789abcdef", b = new Array(256);
      for (let x = 0; x < 16; ++x) {
        const T = x * 16;
        for (let L = 0; L < 16; ++L)
          b[T + L] = B[x] + B[L];
      }
      return b;
    })();
    function Te(B) {
      return typeof BigInt > "u" ? Ve : B;
    }
    function Ve() {
      throw new Error("BigInt not supported");
    }
  })(Ea)), Ea;
}
var Bd = Md(), Pa = { exports: {} }, ss;
function Id() {
  if (ss) return Pa.exports;
  ss = 1;
  var r = Pa.exports = {}, e, t;
  function i() {
    throw new Error("setTimeout has not been defined");
  }
  function o() {
    throw new Error("clearTimeout has not been defined");
  }
  (function() {
    try {
      typeof setTimeout == "function" ? e = setTimeout : e = i;
    } catch {
      e = i;
    }
    try {
      typeof clearTimeout == "function" ? t = clearTimeout : t = o;
    } catch {
      t = o;
    }
  })();
  function a(E) {
    if (e === setTimeout)
      return setTimeout(E, 0);
    if ((e === i || !e) && setTimeout)
      return e = setTimeout, setTimeout(E, 0);
    try {
      return e(E, 0);
    } catch {
      try {
        return e.call(null, E, 0);
      } catch {
        return e.call(this, E, 0);
      }
    }
  }
  function p(E) {
    if (t === clearTimeout)
      return clearTimeout(E);
    if ((t === o || !t) && clearTimeout)
      return t = clearTimeout, clearTimeout(E);
    try {
      return t(E);
    } catch {
      try {
        return t.call(null, E);
      } catch {
        return t.call(this, E);
      }
    }
  }
  var c = [], g = !1, h, m = -1;
  function S() {
    !g || !h || (g = !1, h.length ? c = h.concat(c) : m = -1, c.length && M());
  }
  function M() {
    if (!g) {
      var E = a(S);
      g = !0;
      for (var O = c.length; O; ) {
        for (h = c, c = []; ++m < O; )
          h && h[m].run();
        m = -1, O = c.length;
      }
      h = null, g = !1, p(E);
    }
  }
  r.nextTick = function(E) {
    var O = new Array(arguments.length - 1);
    if (arguments.length > 1)
      for (var N = 1; N < arguments.length; N++)
        O[N - 1] = arguments[N];
    c.push(new I(E, O)), c.length === 1 && !g && a(M);
  };
  function I(E, O) {
    this.fun = E, this.array = O;
  }
  I.prototype.run = function() {
    this.fun.apply(null, this.array);
  }, r.title = "browser", r.browser = !0, r.env = {}, r.argv = [], r.version = "", r.versions = {};
  function _() {
  }
  return r.on = _, r.addListener = _, r.once = _, r.off = _, r.removeListener = _, r.removeAllListeners = _, r.emit = _, r.prependListener = _, r.prependOnceListener = _, r.listeners = function(E) {
    return [];
  }, r.binding = function(E) {
    throw new Error("process.binding is not supported");
  }, r.cwd = function() {
    return "/";
  }, r.chdir = function(E) {
    throw new Error("process.chdir is not supported");
  }, r.umask = function() {
    return 0;
  }, Pa.exports;
}
var Ed = Id();
const Pd = /* @__PURE__ */ Fi(Ed);
window.Buffer || (window.Buffer = Bd.Buffer);
window.process || (window.process = Pd);
window.global || (window.global = window);
export {
  Ei as $,
  zt as a,
  Bd as b
};
