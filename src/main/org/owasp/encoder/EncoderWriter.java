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

import java.io.FilterWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.CharBuffer;

/**
 * EncoderWriter -- a filtering writer that encodes each character is
 * sees using a given encoder.  This class is intentionally package
 * private.  Use Encoder.wrap(Writer) to instantiate.
 *
 * @author Jeffrey Ichnowski
 * @version $Revision: 8 $
 */
final class EncoderWriter extends FilterWriter {

    /**
     * The encoder to encode all character input
     */
    private final Encoder _encoder;

    /**
     * Tracks the last buffer used as an argument to the
     * write(char[]), write(CharSequence) and write(String) methods.
     * Used to identify when we can reuse the _wrapBuffer.
     */
    private transient Object _wrappedObject;

    /**
     * A CharBuffer that is used to wrap char[] inputs into
     * CharSequence implementations.
     */
    private transient CharBuffer _wrapBuffer;

    /**
     * A StringBuilder used to wrap single character inputs in
     * CharSequence implementations.
     */
    private transient StringBuilder _wrapChar;

    /**
     * Creates an EncoderWriter that encodes all input through the
     * specified encoder before passing on to the given writer.
     */
    EncoderWriter(Encoder enc, Writer out) {
        super(out);
        _encoder = enc;
    }

    /** {@inheritDoc} */
    @Override
    public void write(char[] cbuf, int off, int len) throws IOException {
        if (_wrappedObject == cbuf) {
            _wrapBuffer.limit(off+len).position(off);
        } else {
            _wrapBuffer = CharBuffer.wrap(cbuf, off, len);
            _wrappedObject = cbuf;
        }

        _encoder.apply(this.out, _wrapBuffer);
    }

    /** {@inheritDoc} */
    @Override
    public void write(int c) throws IOException {
        // Don't use _wrapBuffer, we do not own the char array that it
        // wraps, it may be reused by the caller.

        if (_wrapChar == null) {
            _wrapChar = new StringBuilder(1);
            _wrapChar.append((char)c);
        } else {
            _wrapChar.setCharAt(0, (char)c);
        }

        _encoder.apply(this.out, _wrapChar);
    }

    /** {@inheritDoc} */
    @Override
    public void write(String str) throws IOException {
        _encoder.apply(this.out, str);
    }

    /** {@inheritDoc} */
    @Override
    public Writer append(CharSequence seq) throws IOException {
        _encoder.apply(this.out, seq);
        return this;
    }

    /** {@inheritDoc} */
    @Override
    public void write(String str, int off, int len) throws IOException {
        if (_wrappedObject == str) {
            _wrapBuffer.limit(off+len).position(off);
        } else {
            _wrapBuffer = CharBuffer.wrap(str, off, off+len);
            _wrappedObject = str;
        }

        _encoder.apply(this.out, _wrapBuffer);
    }

    /** {@inheritDoc} */
    @Override
    public Writer append(CharSequence seq, int start, int end) throws IOException {
        if (_wrappedObject == seq) {
            _wrapBuffer.limit(end).position(start);
        } else {
            _wrapBuffer = CharBuffer.wrap(seq, start, end);
            _wrappedObject = seq;
        }

        _encoder.apply(this.out, _wrapBuffer);
        return this;
    }

} // EncoderWriter
