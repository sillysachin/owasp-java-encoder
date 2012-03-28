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
    /** Encoded length when a single-digit is output. */
    static final int SINGLE_DIGIT_ENCODE_LENGTH = 4;
    /** Encoded length when two digits are required to escape an input. */
    static final int DOUBLE_DIGIT_ENCODE_LENGTH = 5;
    /** Encoded length when 4 digits are required to escape the input. */
    static final int TRIPLE_DIGIT_ENCODE_LENGTH = 6;
    /** Length of an ampersand after encoding. */
    static final int AMP_ENCODE_LENGTH = 5;
    /** Length of the less-than sign when encoded. */
    static final int LT_ENCODE_LENGTH = 4;
    /** Length of the greater-than sign when encoded. */
    static final int GT_ENCODE_LENGTH = 4;

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
            switch (ch) {
            case '\t':
                if (j+SINGLE_DIGIT_ENCODE_LENGTH > m) {
                    return overflow(input, i, output, j);
                }
                out[j++] = '&';
                out[j++] = '#';
                out[j++] = (char)(ch % 10 + '0');
                out[j++] = ';';
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
                if (j+AMP_ENCODE_LENGTH > m) {
                    return overflow(input, i, output, j);
                }
                out[j++] = '&';
                out[j++] = 'a';
                out[j++] = 'm';
                out[j++] = 'p';
                out[j++] = ';';
                break;

            case '<':
                if (j+LT_ENCODE_LENGTH > m) {
                    return overflow(input, i, output, j);
                }
                out[j++] = '&';
                out[j++] = 'l';
                out[j++] = 't';
                out[j++] = ';';
                break;

            case '>':
                if (j+GT_ENCODE_LENGTH > m) {
                    return overflow(input, i, output, j);
                }
                out[j++] = '&';
                out[j++] = 'g';
                out[j++] = 't';
                out[j++] = ';';
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
