package com.eduray.passsafe;

import android.util.Log;

import java.math.BigDecimal;

public class PasswordGenerator {
    private static final String LOG_TAG = PasswordGenerator.class.getName();

    private static final String CONTENT_HEX = "0123456789abcdef";
    private static final String CONTENT_LETTER = "abcdefghijklmnopqrstuvwxyz";
    private static final String CONTENT_NUMBER = "0123456789";
    private static final String CONTENT_MIX = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static final String CONTENT_TYPE_HEX = "hex";
    private static final String CONTENT_TYPE_LETTER = "letter";
    private static final String CONTENT_TYPE_NUMBER = "number";
    private static final String CONTENT_TYPE_MIX = "mix";

    private String contentType = null;

    private static int chrsz = 8;
    private static int globalArrayLength = 0;

    public PasswordGenerator(String contentType) {
        Log.e(LOG_TAG, "contentType = " + contentType);
        if (contentType == null || contentType.equals("")) {
            contentType = CONTENT_TYPE_HEX;
        }
        this.contentType = contentType;
    }

    public String hex_md5(String value) {
        Log.e(LOG_TAG, "hex_md5,param = " + value);
        return binl2hex(core_md5(str2binl(value), value.length() * chrsz));
    }

    /*
     * Convert a string to an array of little-endian words If chrsz is ASCII,
     * characters >255 have their hi-byte silently ignored.
     */
    private int[] str2binl(String str) {
        globalArrayLength = generateArrayLength(str);

        Log.e(LOG_TAG, "arrayLength = " + globalArrayLength);

        int[] tempResult = new int[globalArrayLength];
        int arrayMaxIndex = 0;
        int mask = (1 << chrsz) - 1;
        for (int i = 0; i < str.length() * chrsz; i += chrsz) {
            int arrayIndex = i >> 5;
            if (arrayIndex > arrayMaxIndex) {
                arrayMaxIndex = arrayIndex;
            }
            tempResult[arrayIndex] |= (str.charAt(i / chrsz) & mask) << (i % 32);
        }

        int[] result = new int[arrayMaxIndex + 1];
        for (int i = 0; i <= arrayMaxIndex; i++) {
            result[i] = tempResult[i];
            Log.e(LOG_TAG, "array[" + i + "] = " + result[i]);
        }

        return result;
    }

    /**
     * generateArrayLength
     *
     * @param str
     * @return
     */
    private int generateArrayLength(String str) {
        int arrayLength = str.length() * chrsz;
        int len1 = arrayLength >> 5;
        int len2 = (((arrayLength + 64) >>> 9) << 4) + 14;
        int len3 = arrayLength + 20;
        if (len1 > arrayLength) {
            arrayLength = len1;
        }
        if (len2 > arrayLength) {
            arrayLength = len2;
        }
        if (len3 > arrayLength) {
            arrayLength = len3;
        }
        int temp = arrayLength / 16;
        if (arrayLength % 16 > 0) {
            temp++;
        }
        arrayLength = temp * 16;
        return arrayLength;
    }

    private int[] core_md5(int[] values, int len) {
        int[] tempValues = new int[globalArrayLength];
        for (int i = 0; i < values.length; i++) {
            tempValues[i] = values[i];
        }

        tempValues[len >> 5] |= 0x80 << ((len) % 32);
        tempValues[(((len + 64) >>> 9) << 4) + 14] = len;

        int a = 1732584193;
        int b = -271733879;
        int c = -1732584194;
        int d = 271733878;

        Log.e(LOG_TAG, "len = " + len + " , x.length = " + values.length);

        for (int i = 0; i < values.length; i += 16) {
            int olda = a;
            int oldb = b;
            int oldc = c;
            int oldd = d;

            a = md5_ff(a, b, c, d, tempValues[i + 0], 7, -680876936);
            d = md5_ff(d, a, b, c, tempValues[i + 1], 12, -389564586);
            c = md5_ff(c, d, a, b, tempValues[i + 2], 17, 606105819);
            b = md5_ff(b, c, d, a, tempValues[i + 3], 22, -1044525330);
            a = md5_ff(a, b, c, d, tempValues[i + 4], 7, -176418897);
            d = md5_ff(d, a, b, c, tempValues[i + 5], 12, 1200080426);
            c = md5_ff(c, d, a, b, tempValues[i + 6], 17, -1473231341);
            b = md5_ff(b, c, d, a, tempValues[i + 7], 22, -45705983);
            a = md5_ff(a, b, c, d, tempValues[i + 8], 7, 1770035416);
            d = md5_ff(d, a, b, c, tempValues[i + 9], 12, -1958414417);
            c = md5_ff(c, d, a, b, tempValues[i + 10], 17, -42063);
            b = md5_ff(b, c, d, a, tempValues[i + 11], 22, -1990404162);
            a = md5_ff(a, b, c, d, tempValues[i + 12], 7, 1804603682);
            d = md5_ff(d, a, b, c, tempValues[i + 13], 12, -40341101);
            c = md5_ff(c, d, a, b, tempValues[i + 14], 17, -1502002290);
            b = md5_ff(b, c, d, a, tempValues[i + 15], 22, 1236535329);

            a = md5_gg(a, b, c, d, tempValues[i + 1], 5, -165796510);
            d = md5_gg(d, a, b, c, tempValues[i + 6], 9, -1069501632);
            c = md5_gg(c, d, a, b, tempValues[i + 11], 14, 643717713);
            b = md5_gg(b, c, d, a, tempValues[i + 0], 20, -373897302);
            a = md5_gg(a, b, c, d, tempValues[i + 5], 5, -701558691);
            d = md5_gg(d, a, b, c, tempValues[i + 10], 9, 38016083);
            c = md5_gg(c, d, a, b, tempValues[i + 15], 14, -660478335);
            b = md5_gg(b, c, d, a, tempValues[i + 4], 20, -405537848);
            a = md5_gg(a, b, c, d, tempValues[i + 9], 5, 568446438);
            d = md5_gg(d, a, b, c, tempValues[i + 14], 9, -1019803690);
            c = md5_gg(c, d, a, b, tempValues[i + 3], 14, -187363961);
            b = md5_gg(b, c, d, a, tempValues[i + 8], 20, 1163531501);
            a = md5_gg(a, b, c, d, tempValues[i + 13], 5, -1444681467);
            d = md5_gg(d, a, b, c, tempValues[i + 2], 9, -51403784);
            c = md5_gg(c, d, a, b, tempValues[i + 7], 14, 1735328473);
            b = md5_gg(b, c, d, a, tempValues[i + 12], 20, -1926607734);

            a = md5_hh(a, b, c, d, tempValues[i + 5], 4, -378558);
            d = md5_hh(d, a, b, c, tempValues[i + 8], 11, -2022574463);
            c = md5_hh(c, d, a, b, tempValues[i + 11], 16, 1839030562);
            b = md5_hh(b, c, d, a, tempValues[i + 14], 23, -35309556);
            a = md5_hh(a, b, c, d, tempValues[i + 1], 4, -1530992060);
            d = md5_hh(d, a, b, c, tempValues[i + 4], 11, 1272893353);
            c = md5_hh(c, d, a, b, tempValues[i + 7], 16, -155497632);
            b = md5_hh(b, c, d, a, tempValues[i + 10], 23, -1094730640);
            a = md5_hh(a, b, c, d, tempValues[i + 13], 4, 681279174);
            d = md5_hh(d, a, b, c, tempValues[i + 0], 11, -358537222);
            c = md5_hh(c, d, a, b, tempValues[i + 3], 16, -722521979);
            b = md5_hh(b, c, d, a, tempValues[i + 6], 23, 76029189);
            a = md5_hh(a, b, c, d, tempValues[i + 9], 4, -640364487);
            d = md5_hh(d, a, b, c, tempValues[i + 12], 11, -421815835);
            c = md5_hh(c, d, a, b, tempValues[i + 15], 16, 530742520);
            b = md5_hh(b, c, d, a, tempValues[i + 2], 23, -995338651);

            a = md5_ii(a, b, c, d, tempValues[i + 0], 6, -198630844);
            d = md5_ii(d, a, b, c, tempValues[i + 7], 10, 1126891415);
            c = md5_ii(c, d, a, b, tempValues[i + 14], 15, -1416354905);
            b = md5_ii(b, c, d, a, tempValues[i + 5], 21, -57434055);
            a = md5_ii(a, b, c, d, tempValues[i + 12], 6, 1700485571);
            d = md5_ii(d, a, b, c, tempValues[i + 3], 10, -1894986606);
            c = md5_ii(c, d, a, b, tempValues[i + 10], 15, -1051523);
            b = md5_ii(b, c, d, a, tempValues[i + 1], 21, -2054922799);
            a = md5_ii(a, b, c, d, tempValues[i + 8], 6, 1873313359);
            d = md5_ii(d, a, b, c, tempValues[i + 15], 10, -30611744);
            c = md5_ii(c, d, a, b, tempValues[i + 6], 15, -1560198380);
            b = md5_ii(b, c, d, a, tempValues[i + 13], 21, 1309151649);
            a = md5_ii(a, b, c, d, tempValues[i + 4], 6, -145523070);
            d = md5_ii(d, a, b, c, tempValues[i + 11], 10, -1120210379);
            c = md5_ii(c, d, a, b, tempValues[i + 2], 15, 718787259);
            b = md5_ii(b, c, d, a, tempValues[i + 9], 21, -343485551);

            a = safe_add(a, olda);
            b = safe_add(b, oldb);
            c = safe_add(c, oldc);
            d = safe_add(d, oldd);
        }
        Log.e(LOG_TAG, "a = " + a + " , b = " + b + " , c = " + c + " , d = "
                + d);
        return new int[]{a, b, c, d};

    }

    /*
     * These functions implement the four basic operations the algorithm uses.
     */
    private int md5_cmn(int q, int a, int b, int x, int s, int t) {
        return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
    }

    private int md5_ff(int a, int b, int c, int d, int x, int s, int t) {
        int result = md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
        Log.e(LOG_TAG, "md5_ff(" + a + "," + b + "," + c + "," + d + "," + x
                + "," + s + "," + t + ")=" + result);
        return result;
    }

    private int md5_gg(int a, int b, int c, int d, int x, int s, int t) {
        int result = md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
        Log.e(LOG_TAG, "md5_gg(" + a + "," + b + "," + c + "," + d + "," + x
                + "," + s + "," + t + ")=" + result);
        return result;
    }

    private int md5_hh(int a, int b, int c, int d, int x, int s, int t) {
        int result = md5_cmn(b ^ c ^ d, a, b, x, s, t);
        Log.e(LOG_TAG, "md5_bh(" + a + "," + b + "," + c + "," + d + "," + x
                + "," + s + "," + t + ")=" + result);
        return result;
    }

    private int md5_ii(int a, int b, int c, int d, int x, int s, int t) {
        int result = md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
        Log.e(LOG_TAG, "md5_ii(" + a + "," + b + "," + c + "," + d + "," + x
                + "," + s + "," + t + ")=" + result);
        return result;
    }

    /*
     * Add integers, wrapping at 2^32. This uses 16-bit operations internally to
     * work around bugs in some JS interpreters.
     */
    private int safe_add(int x, int y) {
        int lsw = (x & 0xFFFF) + (y & 0xFFFF);
        int msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        int result = (msw << 16) | (lsw & 0xFFFF);
        Log.e(LOG_TAG, "safe_add(" + x + "," + y + ")=" + result);
        return result;
    }

    /*
     * Bitwise rotate a 32-bit number to the left.
     */
    private int bit_rol(int num, int cnt) {
        int result = (num << cnt) | (num >>> (32 - cnt));
        Log.e(LOG_TAG, "bit_rol(" + num + "," + cnt + ")=" + result);
        return result;
    }

    private String getPasswordBaseContent() {
        String content = null;
        if (CONTENT_TYPE_HEX.equals(contentType)) {
            content = CONTENT_HEX;
        } else if (CONTENT_TYPE_LETTER.equals(contentType)) {
            content = CONTENT_LETTER;
        } else if (CONTENT_TYPE_NUMBER.equals(contentType)) {
            content = CONTENT_NUMBER;
        } else if (CONTENT_TYPE_MIX.equals(contentType)) {
            content = CONTENT_MIX;
        } else {
            content = CONTENT_HEX;
        }
        Log.e(LOG_TAG, "getPasswordBaseContent( " + contentType + " ) = " + content);
        return content;
    }

    /*
     * Convert an array of little-endian words to a hex string.
     */
    private String binl2hex(int[] binArray) {
        Log.e(LOG_TAG, "binl2hex() , binArray length =" + binArray.length);
        String baseContent = getPasswordBaseContent();
        int baseContentLength = baseContent.length();
        Log.e(LOG_TAG, "binl2hex() , get base content length =" + baseContentLength);
        int[] indexes = getContentIndexs(binArray);
        Log.e(LOG_TAG, "binl2hex() , get indexes length =" + indexes.length);
        int indexStep = baseContentLength / 16;
        if (baseContentLength % 16 > 0) {
            indexStep++;
        }
        if (indexStep < 1) {
            indexStep = 1;
        }
        Log.e(LOG_TAG, "binl2hex() , indexes step =" + indexStep);
        String str = "";

        int pos = 0;
        for (int i = 0; i < indexes.length; i++) {
            int step = i % indexStep;
            int index = 16 * step;
            Log.e(LOG_TAG, "index " + i + " , step is " + step + " , index base is " + index);
            if (baseContentLength != 16 && step == (indexStep - 1)) {
                int newIndex = index + (indexes[i] * 100 * (baseContentLength % 16)) / 1600;
                Log.e(LOG_TAG, "scale index from " + (index + indexes[i]) + " to " + newIndex);
                index = newIndex;
            } else {
                index += indexes[i];
                Log.e(LOG_TAG, "original index is " + index);
            }

            str += baseContent.charAt(index);
        }
        return str;
    }

    private int[] getContentIndexs(int[] binArray) {
        int[] indexes = new int[binArray.length * 8];
        for (int i = 0; i < binArray.length * 4; i++) {
            int binIndex = i >> 2;
            int binValue = binArray[binIndex];
            int index1 = (binValue >> ((i % 4) * 8 + 4)) & 0xF;
            int index2 = (binValue >> ((i % 4) * 8)) & 0xF;
            indexes[2 * i] = index1;
            indexes[2 * i + 1] = index2;
        }
        return indexes;
    }
}
