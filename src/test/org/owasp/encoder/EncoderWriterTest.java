// Copyright (c) 2010 SuccessFactors, Inc.
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
//     * Neither the name of the SuccessFactors, Inc. nor the names of
//       its contributors may be used to endorse or promote products
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

import java.io.StringWriter;
import java.io.Writer;

import junit.framework.TestCase;

/**
 * EncoderWriterTest
 *
 * @author Jeffrey Ichnowski
 * @version $Revision: 8 $
 */
public class EncoderWriterTest extends TestCase {

    public void testWriteArray() throws Exception {
        StringWriter out = new StringWriter();
        Writer ew = Encoder.XML.wrap(out);

        ew.write("<>&".toCharArray());

        assertEquals("&lt;&gt;&amp;", out.toString());
    }


    public void testWriteChar() throws Exception {
        StringWriter out = new StringWriter();
        Writer ew = Encoder.XML.wrap(out);

        ew.write('<');

        assertEquals("&lt;", out.toString());        
    }


    public void testWriteArrayPart() throws Exception {
        StringWriter out = new StringWriter();
        Writer ew = Encoder.XML.wrap(out);

        char[] array = "abc<>&xyz".toCharArray();
        ew.write(array, 3, 3);
        ew.write(array, 4, 1);

        assertEquals("&lt;&gt;&amp;&gt;", out.toString());        
    }


    public void testWriteString() throws Exception {
        StringWriter out = new StringWriter();
        Writer ew = Encoder.XML.wrap(out);

        ew.write("<>&");

        assertEquals("&lt;&gt;&amp;", out.toString());
    }


    public void testWriteStringPart() throws Exception {
        StringWriter out = new StringWriter();
        Writer ew = Encoder.XML.wrap(out);

        String str = "abc<>&xyz"; 
        ew.write(str, 3, 3);
        ew.write(str, 4, 1);

        assertEquals("&lt;&gt;&amp;&gt;", out.toString());
    }


    public void testAppendChar() throws Exception {
        StringWriter out = new StringWriter();
        Writer ew = Encoder.XML.wrap(out);

        ew.append('<');

        assertEquals("&lt;", out.toString());
    }


    public void testAppendString() throws Exception {
        StringWriter out = new StringWriter();
        Writer ew = Encoder.XML.wrap(out);

        ew.append("<>&");

        assertEquals("&lt;&gt;&amp;", out.toString());
    }


    public void testAppendStringPart() throws Exception {
        StringWriter out = new StringWriter();
        Writer ew = Encoder.XML.wrap(out);

        // append(seq, START, END); (not offset, len)
        CharSequence seq = "abc<>&xyz";
        ew.append(seq, 3, 6);
        ew.append(seq, 4, 5);

        assertEquals("&lt;&gt;&amp;&gt;", out.toString());        
    }
    
} // EncoderWriterTest
