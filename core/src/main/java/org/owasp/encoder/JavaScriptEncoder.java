// Copyright (c) 2012 Jeff Ichnowski
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//     * Redistributions of source code must retain the above
//       copyright notice, this list of conditions and the following
//       disclaimer.
//
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials
//       provided with the distribution.
//
//     * Neither the name of the OWASP nor the names of its
//       contributors may be used to endorse or promote products
//       derived from this software without specific prior written
//       permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.

package org.owasp.encoder;

import java.nio.CharBuffer;
import java.nio.charset.CoderResult;

/**
 * JavaScriptEncoder -- An encoder for JavaScript string contexts.
 *
 * Created: 12/6/11
 *
 * @author jeffi
 */
class JavaScriptEncoder extends Encoder {

    /**
     * Encoded length for single-character backslash escapes.
     */
    static final int CHARS_PER_SLASH_ESCAPE = 2;
    /**
     * Encoded length for hexadecimal escapes (e.g. "\x12")
     */
    static final int CHARS_PER_HEX_ESCAPE = 4;
    /**
     * Encoded length for Unicode escapes.
     */
    static final int CHARS_PER_U_ESCAPE = 6;

    /**
     * The maximum code-point that is encoded using hex escapes.
     */
    static final int MAX_HEX_ENCODED_CHAR = 0xff;

    /**
     * Mode of operation constants for the JavaScriptEncoder.
     */
    static enum Mode {
        /**
         * Standard encoding of JavaScript Strings.  Escape sequences are chosen
         * according to what is the shortest sequence possible for the character.
         */
        SOURCE,

        /**
         * Encoding for use in HTML attributes.  Quote characters are escaped
         * using hex encodes instead of backslashes.  The alternate would be
         * to use a sequence of encodes that would actually be longer.  In this
         * mode double-quote is "\x22" and single-quote is "\x27".  (In HTML
         * attributes the alternate would be encoding "\"" and "\'" with entity
         * escapes to "\&amp;#34;" and "\&amp;39;").
         */
        ATTRIBUTE,

        /**
         * Encoding for use in HTML script blocks.  The main concern here is
         * permaturely terminating a script block with a closing "&lt;/" inside
         * the string.  This encoding escapes "/" as "\/" to prevent such
         * termination.
         */
        BLOCK,

        /**
         * Encodes for use in either HTML script attributes or blocks.
         * Essentially this is both special escapes from HTML_ATTRIBUTE and
         * HTML_CONTENT combined.
         */
        HTML,
        ;
    }

    /**
     * The mode of operations--used for toString implementation.
     */
    private final Mode _mode;
    /**
     * True if quotation characters should be hex encoded.  Hex encoding
     * quotes allows JavaScript to be included in XML attributes without
     * additional XML-based encoding.
     */
    private final boolean _hexEncodeQuotes;
    /**
     * True if the forward-slash ("/") character should be encoded
     * (as "\/").  Encoding forward-slashes prevents them from being
     * interpreted as part of a close tag by HTML parsers.  Without
     * this a string containing "&lt;/xyz>" could result in an HTML
     * parser terminating a script block early.
     */
    private final boolean _escapeForwardSlash;
    /**
     * This value, along with {@link #_uEncodedInvalidMax} defines an
     * invalid range in the \\u encoded block.  When encoding for ASCII
     * this range is effectively all of Unicode.  When not encoding for
     * ASCII, this range is the range that includes the line and paragraph
     * separator characters.
     */
    private final char _uEncodedInvalidMin;
    /**
     * This value, along with {@link #_uEncodedInvalidMin} defines an
     * invalid range in the \\u encoded block.  When encoding for ASCII
     * this range is effectively all of Unicode.  When not encoding for
     * ASCII, this range is the range that includes the line and paragraph
     * separator characters.
     */
    private final char _uEncodedInvalidMax;

    /**
     * Default constructor--equivalent to
     * {@code new JavaScriptEncoder(Mode.SOURCE, false)}.
     */
    JavaScriptEncoder() {
        this(Mode.SOURCE, false);
    }

    /**
     * Constructs a new JavaScriptEncoder for the specified contextual mode.
     *
     * @param mode the mode of operation
     * @param asciiOutput true if only ASCII characters should be included
     * in the output (all code-points outside the ASCII range will be
     * encoded).
     */
    JavaScriptEncoder(Mode mode, boolean asciiOutput) {
        _mode = mode;
        _hexEncodeQuotes = (mode == Mode.ATTRIBUTE || mode == Mode.HTML);
        _escapeForwardSlash = (mode == Mode.BLOCK || mode == Mode.HTML);

        _uEncodedInvalidMin = asciiOutput ? (Unicode.MAX_ASCII+1) : Unicode.LINE_SEPARATOR;
        _uEncodedInvalidMax = asciiOutput ? Character.MAX_VALUE : Unicode.PARAGRAPH_SEPARATOR;
    }

    @Override
    protected int maxEncodedLength(int n) {
        // Because of LINE_SEPARATOR and PARAGRAPH_SEPARATOR a unicode
        // escape might be required.
        return n * CHARS_PER_U_ESCAPE;
    }

    @Override
    protected int firstEncodedOffset(String input, int off, int len) {
        final int n = off + len;
        for (int i=off ; i<n ; ++i) {
            char ch = input.charAt(i);
            if (ch >= ' ') {
                if (ch == '\\' || ch == '\'' || ch == '\"' ||
                    (ch == '/' && _escapeForwardSlash) ||
                    (ch >= _uEncodedInvalidMin && ch <= _uEncodedInvalidMax) ||
                    (ch == '&' && _mode != Mode.SOURCE))
                {
                    return i;
                }
                // valid
            } else {
                return i;
            }
        }
        return n;
    }

    @Override
    protected CoderResult encodeArrays(CharBuffer input, CharBuffer output, boolean endOfInput) {
        final char[] in = input.array();
        final char[] out = output.array();
        int i = input.arrayOffset() + input.position();
        final int n = input.arrayOffset() + input.limit();
        int j = output.arrayOffset() + output.position();
        final int m = output.arrayOffset() + output.limit();

        for ( ; i<n ; ++i) {
            char ch = in[i];
            if (ch >= ' ' && ch < _uEncodedInvalidMin || ch > _uEncodedInvalidMax) {
                if (ch == '\\' || (ch == '/' && _escapeForwardSlash)) {
                    if (j+2 > m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = ch;
                } else if (ch == '\'' || ch == '\"') {
                    if (_hexEncodeQuotes) {
                        if (j + CHARS_PER_HEX_ESCAPE > m) {
                            return overflow(input, i, output, j);
                        }
                        out[j++] = '\\';
                        out[j++] = 'x';
                        out[j++] = HEX[ch >>> HEX_SHIFT];
                        out[j++] = HEX[ch & HEX_MASK];
                    } else {
                        if (j + CHARS_PER_SLASH_ESCAPE > m) {
                            return overflow(input, i, output, j);
                        }
                        out[j++] = '\\';
                        out[j++] = ch;
                    }
                } else if (ch == '&' && _mode != Mode.SOURCE) {
                    out[j++] = '\\';
                    out[j++] = 'x';
                    out[j++] = '2'; //HEX[ch >>> HEX_SHIFT];
                    out[j++] = '6'; //HEX[ch & HEX_MASK];
                } else {
                    if (j >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = ch;
                }
            } else {
                switch (ch) {
                case '\b':
                    if (j+CHARS_PER_SLASH_ESCAPE > m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 'b';
                    break;
                case '\t':
                    if (j+CHARS_PER_SLASH_ESCAPE > m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 't';
                    break;
                case '\n':
                    if (j+CHARS_PER_SLASH_ESCAPE > m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 'n';
                    break;

                // Per Mike Samuel "\v should not be used since some
                // versions of IE treat it as a literal letter 'v'"
//                case 0x0b: // '\v'
//                    if (j+1 >= m) {
//                        return overflow(input, i, output, j);
//                    }
//                    out[j++] = '\\';
//                    out[j++] = 'v';
//                    break;
                case '\f':
                    if (j+CHARS_PER_SLASH_ESCAPE > m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 'f';
                    break;
                case '\r':
                    if (j+CHARS_PER_SLASH_ESCAPE > m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 'r';
                    break;
                default:
                    if (ch <= MAX_HEX_ENCODED_CHAR) {
                        if (j+CHARS_PER_HEX_ESCAPE > m) {
                            return overflow(input, i, output, j);
                        }
                        out[j++] = '\\';
                        out[j++] = 'x';
                        out[j++] = HEX[ch >>> HEX_SHIFT];
                        out[j++] = HEX[ch & HEX_MASK];
                    } else {
                        if (j+CHARS_PER_U_ESCAPE > m) {
                            return overflow(input, i, output, j);
                        }
                        out[j++] = '\\';
                        out[j++] = 'u';
                        out[j++] = HEX[ch >>> (3*HEX_SHIFT)];
                        out[j++] = HEX[(ch >>> (2*HEX_SHIFT)) & HEX_MASK];
                        out[j++] = HEX[(ch >>> HEX_SHIFT) & HEX_MASK];
                        out[j++] = HEX[ch & HEX_MASK];
                    }
                    break;
                }
            }
        }

        return underflow(input, i, output, j);
    }

    @Override
    public String toString() {
        return "JavaScriptEncoder(mode="+_mode+","+(_uEncodedInvalidMax == Character.MAX_VALUE ?"ASCII":"UNICODE")+")";
    }
}
