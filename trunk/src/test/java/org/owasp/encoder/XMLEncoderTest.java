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

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * XMLEncoderTest -- test suite for the XMLEncoder.
 *
 * @author Jeff Ichnowski
 */
public class XMLEncoderTest extends TestCase {
    public static Test suite() {
        TestSuite suite = new TestSuite();
        for (XMLEncoder.Mode mode : XMLEncoder.Mode.values()) {
            EncoderTestSuiteBuilder builder = new EncoderTestSuiteBuilder(new XMLEncoder(mode), "-safe-", "-&-")
                .encode("safe", "safe")
                .encode("unencoded &amp; encoded", "unencoded & encoded")
                .encode("invalid-control-characters", " b ", "\0b\26")
                .encode("valid-surrogate-pair", "\ud800\udc00", "\ud800\udc00")
                .encode("missing-low-surrogate", " ", "\ud800")
                .encode("missing-high-surrogate", " ", "\udc00")
                .encode("valid-upper-char", "\ufffd", "\ufffd")
                .encode("invalid-upper-char", " ", "\uffff")

                .invalid(0, 0x1f)
                .valid("\t\r\n")
                .valid(' ', Character.MAX_CODE_POINT)
                .invalid(0x7f, 0x9f)
                .valid("\u0085")
                .invalid(Character.MIN_SURROGATE, Character.MAX_SURROGATE)
                .invalid(0xfdd0, 0xfdef)
                .invalid(0xfffe, 0xffff)
                .invalid(0x1fffe, 0x1ffff)
                .invalid(0x2fffe, 0x2ffff)
                .invalid(0x3fffe, 0x3ffff)
                .invalid(0x4fffe, 0x4ffff)
                .invalid(0x5fffe, 0x5ffff)
                .invalid(0x6fffe, 0x6ffff)
                .invalid(0x7fffe, 0x7ffff)
                .invalid(0x8fffe, 0x8ffff)
                .invalid(0x9fffe, 0x9ffff)
                .invalid(0xafffe, 0xaffff)
                .invalid(0xbfffe, 0xbffff)
                .invalid(0xcfffe, 0xcffff)
                .invalid(0xdfffe, 0xdffff)
                .invalid(0xefffe, 0xeffff)
                .invalid(0xffffe, 0xfffff)
                .invalid(0x10fffe, 0x10ffff);

            switch (mode) {
            case ALL:
                builder.encoded("&><\'\"")
                    .encode("&amp;", "&")
                    .encode("&gt;", ">")
                    .encode("&lt;", "<")
                    .encode("&#39;", "\'")
                    .encode("&#34;", "\"");
                break;
            case CONTENT:
                builder.encoded("&><")
                    .encode("&amp;", "&")
                    .encode("&gt;", ">")
                    .encode("&lt;", "<")
                    .encode("\'", "\'")
                    .encode("\"", "\"");
                break;
            case ATTRIBUTE:
                builder.encoded("&<\'\"")
                    .encode("&amp;", "&")
                    .encode(">", ">")
                    .encode("&lt;", "<")
                    .encode("&#39;", "\'")
                    .encode("&#34;", "\"");
                break;
            case SINGLE_QUOTED_ATTRIBUTE:
                builder.encoded("&<\'")
                    .encode("&amp;", "&")
                    .encode(">", ">")
                    .encode("&lt;", "<")
                    .encode("&#39;", "\'")
                    .encode("\"", "\"");
                break;
            case DOUBLE_QUOTED_ATTRIBUTE:
                builder.encoded("&<\"")
                    .encode("&amp;", "&")
                    .encode(">", ">")
                    .encode("&lt;", "<")
                    .encode("\'", "\'")
                    .encode("&#34;", "\"");
                break;
            default:
                throw new AssertionError("untested mode: "+mode);
            }

            suite.addTest(builder
                .validSuite()
                .invalidSuite(XMLEncoder.INVALID_CHARACTER_REPLACEMENT)
                .encodedSuite()
                .build());
        }
        return suite;
    }
}
