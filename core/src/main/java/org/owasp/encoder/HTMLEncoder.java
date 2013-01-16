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
 * <p>HTMLEncoder -- an encoder for HTML contexts.  Currently most
 * HTML-based contexts are properly handled by {@line XMLEncoder}.
 * The remaining HTML-specific context of "unquoted attributes" could
 * not be added to the XMLEncoder without slowing it down.  This class
 * implements that remaining context: <strong>unquoted attribute
 * values</strong>.</p>
 *
 * <p>Note: because this context is likely small strings, and
 * hopefully rarely used, no effort was put into optimizing this
 * encoder.</p>
 *
 * @author Jeff Ichnowski
 */
class HTMLEncoder extends Encoder {
    /** Encoded length when two digits are required to escape an input. */
    private static final int DOUBLE_DIGIT_ENCODE_LENGTH = 5;
    /** Encoded length when 4 digits are required to escape the input. */
    private static final int TRIPLE_DIGIT_ENCODE_LENGTH = 6;

    /** Encoding for '\t'. */
    private static final char[] TAB = "&#9;".toCharArray();
    /** Encoding for '&amp;'. */
    private static final char[] AMP = "&amp;".toCharArray();
    /** Encoding for '&lt;'. */
    private static final char[] LT = "&lt;".toCharArray();
    /** Encoding for '&gt;'. */
    private static final char[] GT = "&gt;".toCharArray();

    // The large table-switch implementation used here is fast to
    // implement but slower at runtime than tuned-for-expected-input
    // encoders that use selective if/else's.  Look at the results of
    // BenchmarkTest to see the difference.  See note in javadoc as to
    // reasoning.

    // On Core i7 (Sandybridge)
    // Baseline is 371.401009 ns/op
    // Benchmarked Encode.forXml: 324.219992 ns/op (-12.70% on baseline)
    // Benchmarked Encode.forHtmlUnquotedAttribute: 821.583263 ns/op (+121.21% on baseline)


    @Override
    int maxEncodedLength(int n) {
        return n*TRIPLE_DIGIT_ENCODE_LENGTH;
    }

    @Override
    int firstEncodedOffset(String input, int off, int len) {
        final int n = off+len;
        for (int i=off ; i<n ; ++i) {
            final char ch = input.charAt(i);

            switch (ch) {
            case '\t': case '\r': case '\f': case '\n': case ' ': case Unicode.NEL:
            case '\"': case '\'':
            case '/': case '=': case '`':
            case '&': case '<': case '>':
                return i;

            case '!': case '#': case '$': case '%':
            case '(': case ')': case '*': case '+':
            case ',': case '-': case '.':

            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
            case ':': case ';': case '?': case '@':

            case 'A': case 'B': case 'C': case 'D': case 'E':
            case 'F': case 'G': case 'H': case 'I': case 'J':
            case 'K': case 'L': case 'M': case 'N': case 'O':
            case 'P': case 'Q': case 'R': case 'S': case 'T':
            case 'U': case 'V': case 'W': case 'X': case 'Y':
            case 'Z':

            case '[': case '\\': case ']': case '^': case '_':

            case 'a': case 'b': case 'c': case 'd': case 'e':
            case 'f': case 'g': case 'h': case 'i': case 'j':
            case 'k': case 'l': case 'm': case 'n': case 'o':
            case 'p': case 'q': case 'r': case 's': case 't':
            case 'u': case 'v': case 'w': case 'x': case 'y':
            case 'z':

            case '{': case '|': case '}': case '~':
                break; // valid

            default:

                if (Character.isHighSurrogate(ch)) {
                    if (i+1 < n) {
                        if (Character.isLowSurrogate(input.charAt(i+1))) {
                            int cp = Character.toCodePoint(ch, input.charAt(i+1));
                            if (Unicode.isNonCharacter(cp)) {
                                return i;
                            } else {
                                ++i;
                            }
                            break;
                        }
                    } else {
                        return i;
                    }
                }

                if (ch <= Unicode.MAX_C1_CTRL_CHAR ||
                    Character.MIN_SURROGATE <= ch && ch <= Character.MAX_SURROGATE ||
                    ch > '\ufffd' ||
                    ('\ufdd0' <= ch && ch <= '\ufdef'))
                {
                    return i;
                }
            }
        }
        return n;
    }

    /**
     * Appends a source array verbatim to the output array, provided there
     * is enough space left.  If the copy is successful, the new offset
     * will be returned, otherwise {@code -j - 1} is returned.  Thus a failure
     * will always be negative, including when {@code j} is 0.
     *
     * @param src the characters to copy
     * @param out the output buffer
     * @param j the offset where to write in the output buffer
     * @param m the write limit
     * @return {@code j + src.length} if successful, {@code -j -1} if not.
     */
    static int append(char[] src, char[] out, int j, int m) {
        final int jAfter = j + src.length;
        if (jAfter > m) {
            return -j - 1;
        }
        System.arraycopy(src, 0, out, j, src.length);
        return jAfter;
    }

    @Override
    CoderResult encodeArrays(
        CharBuffer input, CharBuffer output, boolean endOfInput)
    {
        final char[] in = input.array();
        final char[] out = output.array();
        int i = input.arrayOffset() + input.position();
        final int n = input.arrayOffset() + input.limit();
        int j = output.arrayOffset() + output.position();
        final int m = output.arrayOffset() + output.limit();

    charLoop:
        for ( ; i<n ; ++i) {
            final char ch = in[i];

            // gigantic switch, hopefully compiled to a tableswitch.
            // this approach appears to be slower than the if/else
            // approach used in the other encoders.  Perhaps an artifact
            // of the CPU's branch predictor, or possible additional
            // overhead of range checking, or having the entire table
            // available to the cache.  If time allows, it would
            // interesting to find out.
            switch (ch) {
            case '\t':
                j = append(TAB, out, j, m);
                if (j < 0) {
                    return overflow(input, i, output, -j-1);
                }
                break;

            case '\r': case '\n': case '\f': case ' ': case '\"': case '\'':
            case '/': case '=': case '`':
                if (j+DOUBLE_DIGIT_ENCODE_LENGTH > m) {
                    return overflow(input, i, output, j);
                }
                out[j++] = '&';
                out[j++] = '#';
                out[j++] = (char)(ch / 10 % 10 + '0');
                out[j++] = (char)(ch % 10 + '0');
                out[j++] = ';';
                break;

            case Unicode.NEL:
                if (j+TRIPLE_DIGIT_ENCODE_LENGTH > m) {
                    return overflow(input, i, output, j);
                }
                out[j++] = '&';
                out[j++] = '#';
                out[j++] = (char)(ch / 100 % 10 + '0');
                out[j++] = (char)(ch / 10 % 10 + '0');
                out[j++] = (char)(ch % 10 + '0');
                out[j++] = ';';
                break;

            case '&':
                j = append(AMP, out, j, m);
                if (j < 0) {
                    return overflow(input, i, output, -j-1);
                }
                break;

            case '<':
                j = append(LT, out, j, m);
                if (j < 0) {
                    return overflow(input, i, output, -j-1);
                }
                break;

            case '>':
                j = append(GT, out, j, m);
                if (j < 0) {
                    return overflow(input, i, output, -j-1);
                }
                break;

            case '!': case '#': case '$': case '%':
            case '(': case ')': case '*': case '+':
            case ',': case '-': case '.':

            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
            case ':': case ';': case '?': case '@':

            case 'A': case 'B': case 'C': case 'D': case 'E':
            case 'F': case 'G': case 'H': case 'I': case 'J':
            case 'K': case 'L': case 'M': case 'N': case 'O':
            case 'P': case 'Q': case 'R': case 'S': case 'T':
            case 'U': case 'V': case 'W': case 'X': case 'Y':
            case 'Z':

            case '[': case '\\': case ']': case '^': case '_':

            case 'a': case 'b': case 'c': case 'd': case 'e':
            case 'f': case 'g': case 'h': case 'i': case 'j':
            case 'k': case 'l': case 'm': case 'n': case 'o':
            case 'p': case 'q': case 'r': case 's': case 't':
            case 'u': case 'v': case 'w': case 'x': case 'y':
            case 'z': case '{': case '|': case '}': case '~':
                if (j >= m) {
                    return overflow(input, i, output, j);
                }
                out[j++] = ch;
                break;
            default:

                if (Character.isHighSurrogate(ch)) {
                    if (i+1 < n) {
                        if (Character.isLowSurrogate(in[i+1])) {
                            int cp = Character.toCodePoint(ch, in[i+1]);
                            if (Unicode.isNonCharacter(cp)) {
                                if (j >= m) {
                                    return overflow(input, i, output, j);
                                }
                                out[j++] = '-';
                                ++i;
                            } else {
                                if (j+1 >= m) {
                                    return overflow(input, i, output, j);
                                }
                                out[j++] = ch;
                                out[j++] = in[++i];
                            }
                            break;
                        }
                    } else if (!endOfInput) {
                        break charLoop;
                    }
                }

                if (j >= m) {
                    return overflow(input, i, output, j);
                }

                if (ch <= Unicode.MAX_C1_CTRL_CHAR ||
                    Character.MIN_SURROGATE <= ch && ch <= Character.MAX_SURROGATE ||
                    ch > '\ufffd' ||
                    ('\ufdd0' <= ch && ch <= '\ufdef'))
                {
                    // invalid
                    out[j++] = '-';
                } else {
                    out[j++] = ch;
                }
            }
        }

        return underflow(input, i, output, j);
    }
}
