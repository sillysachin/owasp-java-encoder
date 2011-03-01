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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

/**
 * Encoder -- character escaping for various contexts. A typical usage example
 * would look like:
 * 
 * <pre>
 * String output = Encoder.XML.apply(input);
 * </pre>
 * 
 * Several variations on the escaping API exist. See class JavaDoc for full
 * details.
 * 
 * @author Jeffrey Ichnowski
 * @version $Revision: 8 $
 */
public abstract class Encoder {

	// TODO: some serious performance clean up... Writing to the
	// Appendables one char at a time can be really slow. Use
	// ThreadLocal buffers or something.

	/**
	 * Mapping from standard escape name to singleton instance.
	 */
	private static final Map<String, Encoder> ENUM_MAP = new HashMap<String, Encoder>();

	/** Hexidecimal array used for hex escapes. */
	static final char[] HEX = "0123456789abcdef".toCharArray();

	/**
	 * Checks if a character is valid in XML. This only tests a single character
	 * in a UTF-16 sequence. It will return true if the character is valid. It
	 * will return false if the character is invalid by itself. Surrogate pair
	 * handling must happen separately. This method is used by XML encoders to
	 * remove characters that are invalid according to the XML
	 * specification--while they won't necessarily introduce XSS, they might
	 * introduce DoS by making the produced XML invalid.
	 * 
	 * @param ch
	 *            the character to test
	 * @return true if the character is valid
	 */
	static final boolean isValidXMLChar(char ch) {
		// [2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] |
		// [#xE000-#xFFFD] | [#x10000-#x10FFFF]

		return ('\u0020' <= ch && ch <= '\ud7ff' || '\ue000' <= ch
				&& ch <= '\ufffd' || ch == '\n' || ch == '\r' || ch == '\t');
	}

	/**
	 * No escaping. This is a simple passthrough from input to output with no
	 * change.
	 */
	public static final Encoder NONE = new Encoder("NONE") {
		/** {@inheritDoc} */
		@Override
		public <T extends Appendable> T apply(T buf, CharSequence text)
				throws IOException {
			buf.append(text);
			return buf;
		}
	};

	/**
	 * Full XML escaping. This escapes "&lt", "&gt;", "&amp", single-quote and
	 * double-quote characters. It is appropriate in XML attributes and content.
	 */
	public static final Encoder XML = new XmlEncoder("XML", XmlEncoder.ALL);

	/**
	 * The minimal XML escaping required for XML content. This only escapes
	 * "&lt;", "&gt;", and "&amp;". It does not escape quotation characters and
	 * is thus not appropriate for XML attributes.
	 */
	public static final Encoder XML_CONTENT = new XmlEncoder("XML_CONTENT",
			XmlEncoder.CONTENT);

	/**
	 * Escaping for XML comments. All characters are allowed in comments, except
	 * occurances of "--". Additionally IE's "conditional comments" (&lt;--[if
	 * IE]>) need to be encoded. Since there is no recognized escape sequence in
	 * the comment context, this encoder changes the characters sequences to
	 * something without meaning.
	 */
	public static final Encoder XML_COMMENT = new Encoder("XML_COMMENT") {
		/** {@inheritDoc} */
		@Override
		public <T extends Appendable> T apply(T buf, CharSequence text)
				throws IOException {
			// TODO: [if IE] et all.
			if (text != null) {
				int lastDash = -1;
				for (int i = 0, n = text.length(); i < n; ++i) {
					char ch = text.charAt(i);
					if (ch == '-') {
						// convert '-' to '~' if the last character
						// was a '-' or we're looking at the first or
						// last character in the buffer.
						if (lastDash == i - 1 || i == n - 1) {
							buf.append('~');
						} else {
							lastDash = i;
							buf.append(ch);
						}
					} else {
						// See the XmlEncode implementation for
						// details. We're only appending valid XML
						// characters (including surrogate pairs) to
						// the output.
						if (isValidXMLChar(ch)) {
							buf.append(ch);
						} else if (i + 1 < n
								&& Character.isSurrogatePair(ch, text
										.charAt(i + 1))) {
							buf.append(ch).append(text.charAt(++i));
						} else {
							buf.append(' ');
						}
					}
				}
			}
			return buf;
		}
	};

	public final static String encodeForXML(String input) {
		return Encoder.XML.apply(input);
	}

	/**
	 * Escaping for a Java String. This replaces newlines with "\n", tabs with
	 * "\t", etc... and non-ascii with "\\u" escapes.
	 */
	public static final Encoder JAVA_STRING = new Encoder("JAVA_STRING") {
		/** {@inheritDoc} */
		@Override
		public <T extends Appendable> T apply(T buf, CharSequence text)
				throws IOException {
			if (text != null) {
				for (int i = 0, n = text.length(); i < n; ++i) {
					char ch = text.charAt(i);
					switch (ch) {
					case '\t':
						buf.append("\\t");
						break;
					case '\b':
						buf.append("\\b");
						break;
					case '\n':
						buf.append("\\n");
						break;
					case '\r':
						buf.append("\\r");
						break;
					case '\f':
						buf.append("\\f");
						break;
					case '\'':
					case '\"':
					case '\\':
						buf.append('\\').append(ch);
						break;
					default:
						if (' ' <= ch && ch <= '~') {
							buf.append(ch);
						} else {
							buf.append("\\u").append(HEX[(ch >> 12) & 0xf])
									.append(HEX[(ch >> 8) & 0xf]).append(
											HEX[(ch >> 4) & 0xf]).append(
											HEX[(ch >> 0) & 0xf]);
						}
					}
				}
			}
			return buf;
		}
	};

	public final static String encodeForJavaString(String input) {
		return Encoder.JAVA_STRING.apply(input);
	}

	/**
	 * Escaping for CDATA sections. CDATA sections allow most content through
	 * without escaping, however a "]]&gt;" tag in the middle of it will
	 * terminate the section. This implementation converts occurances of
	 * "]]&gt;" to "]]&gt;]]&lt;![CDATA[&gt;". This, when parsed by a compliant
	 * XML parser, will look to the application as "]]&gt;" (possibly over
	 * multiple character events).
	 */
	public static final Encoder CDATA = new Encoder("CDATA") {
		/** {@inheritDoc} */
		@Override
		public <T extends Appendable> T apply(T buf, CharSequence text)
				throws IOException {
			if (text != null) {
				int state = 0;
				for (int i = 0, n = text.length(); i < n; ++i) {
					char ch = text.charAt(i);
					switch (state) {
					case 0:
						if (ch == ']') {
							state = 1;
						}
						break;
					case 1:
						if (ch == ']') {
							state = 2;
						} else {
							state = 0;
						}
						break;
					case 2:
						if (ch == '>') {
							state = 0;
							buf.append("><![CDATA[");
						} else if (ch != ']') {
							state = 0;
						}
						break;
					default:
						throw new IllegalStateException();
					}
					buf.append(ch);
				}
			}
			return buf;
		}
	};

	public final static String encodeForXML_CDATA(String input) {
		return Encoder.CDATA.apply(input);
	}

	/**
	 * Escaping for JavaScript strings. Similar to JAVA_STRING. Note, this does
	 * not include escaping for XML. Typically this needs to be sequenced with
	 * one of those escapes when used in XHTML context.
	 */
	public static final Encoder JAVASCRIPT = new Encoder("JAVASCRIPT") {
		/** {@inheritDoc} */
		@Override
		public <T extends Appendable> T apply(T buf, CharSequence text)
				throws IOException {
			if (text != null) {
				for (int i = 0, n = text.length(); i < n; ++i) {
					char ch = text.charAt(i);
					switch (ch) {
					case '\t':
						buf.append("\\t");
						break;
					case '\n':
						buf.append("\\n");
						break;
					case '\r':
						buf.append("\\r");
						break;
					case '\'':
					case '\"':
					case '\\':
						buf.append('\\').append(ch);
						break;
					case '/':
						// convert "</" to "<\/" to avoid having "</"
						// (and "</script>") appear in the output
						if (i > 0 && text.charAt(i - 1) == '<') {
							buf.append('\\');
						}
						buf.append(ch);
						break;
					case '>':
						// convert "]]>" to "]]\>" to avoid a CDATA end
						if (i > 1 && text.charAt(i - 1) == ']'
								&& text.charAt(i - 2) == ']') {
							buf.append('\\');
						}
						buf.append(ch);
						break;
					default:
						if (' ' <= ch && ch <= '~') {
							buf.append(ch);
						} else {
							buf.append("\\u").append(HEX[(ch >> 12) & 0xf])
									.append(HEX[(ch >> 8) & 0xf]).append(
											HEX[(ch >> 4) & 0xf]).append(
											HEX[(ch >> 0) & 0xf]);
						}
					}
				}
			}
			return buf;
		}
	};

	public final static String encodeForJavascript(String input) {
		return Encoder.JAVASCRIPT.apply(input);
	}

	/**
	 * Escaping for a XHTML &lt;script&gt; block. Inside a script block, the
	 * sequence "&lt;/" is likely to cause the script block to be prematurely
	 * terminated (in most browsers).
	 */
	public static final Encoder SCRIPT_CODE = new Encoder("SCRIPT_CODE") {
		/** {@inheritDoc} */
		@Override
		public <T extends Appendable> T apply(T buf, CharSequence text)
				throws IOException {
			if (text != null) {
				for (int i = 0, n = text.length(); i < n; ++i) {
					char ch = text.charAt(i);
					if (ch == '/' && i > 0 && text.charAt(i - 1) == '<') {
						// insert a space between '<' and '/'
						buf.append(' ');
					}
					buf.append(ch);
				}
			}
			return buf;
		}
	};

	//
	// TODO: Fix this name
	//
	public final static String encodeForScriptCode(String input) {
		return Encoder.SCRIPT_CODE.apply(input);
	}

	/**
	 * Encodes a Uniform Resource Identifier (URI) component by replacing each
	 * instance of certain characters by one, two, or three escape sequences
	 * representing the UTF-8 encoding of the character.
	 * 
	 * (Javadoc description from Mozilla.org's description for the JavaScript
	 * method of the same name.)
	 */
	public static final Encoder URI_COMPONENT = new EncodeURIComponent();

	/**
	 * Encodes a Uniform Resource Identifier (URI) by replacing each instance of
	 * certain characters by one, two, or three escape sequences representing
	 * the UTF-8 encoding of the character.
	 * 
	 * Note that encodeURI by itself cannot form proper HTTP GET and POST
	 * requests, such as for XMLHTTPRequests, because "&", "+", and "=" are not
	 * encoded, which are treated as special characters in GET and POST
	 * requests. encodeURIComponent, however, does encode these characters.
	 * These behaviors are most likely not consistent across browsers.
	 * 
	 * (Javadoc description from Mozilla.org's description for the JavaScript
	 * method of the same name.)
	 */
	public static final Encoder URI = new EncodeURI();

	/**
	 * Encodes a URI suitable for an XTHML attribute. This is the sequence URI
	 * -> XML. Note the URI encoding is done using UTF-8 encoding. If another
	 * encoding is needed, <code>forSequence(forURI(encoding), XML)</code>
	 * should be used.
	 */
	public static final Encoder XHTML_URI = forSequence(URI, XML);

	/**
	 * Implements a sequence of escapes applied in succession.
	 */
	static class Sequence extends Encoder {
		private Encoder[] _escapes;

		Sequence(Encoder... types) {
			int count = 0;

			for (Encoder type : types) {
				if (type == null) {
					throw new NullPointerException();
				}
				if (type instanceof Sequence) {
					count += ((Sequence) type)._escapes.length;
				} else {
					count++;
				}
			}

			_escapes = new Encoder[count];
			int i = 0;
			for (Encoder type : types) {
				if (type instanceof Sequence) {
					Encoder[] sub = ((Sequence) type)._escapes;
					System.arraycopy(sub, 0, _escapes, i, sub.length);
					i += sub.length;
				} else {
					_escapes[i++] = type;
				}
			}
		}

		/** {@inheritDoc} */
		@Override
		public <T extends Appendable> T apply(T buf, CharSequence text)
				throws IOException {
			StringBuilder tmp1 = new StringBuilder(text.length() * 2);
			_escapes[0].apply(tmp1, text);
			int n = _escapes.length - 1;
			if (n == 1) {
				return _escapes[1].apply(buf, tmp1);
			}

			StringBuilder tmp2 = new StringBuilder(text.length() * 2);
			for (int i = 1;;) {
				_escapes[i].apply(tmp2, tmp1);
				if (++i == n) {
					return _escapes[i].apply(buf, tmp2);
				}
				tmp1.setLength(0);
				_escapes[i].apply(tmp1, tmp2);
				if (++i == n) {
					return _escapes[i].apply(buf, tmp1);
				}
				tmp2.setLength(0);
			}
		}
	}

	/**
	 * XML Entity encoder. This is the implemenation class for the XML and
	 * XML_CONTENT singletons.
	 */
	static class XmlEncoder extends Encoder {

		static final int CONTENT = 0;
		static final int SINGLE_QUOTE = 1;
		static final int DOUBLE_QUOTE = 2;
		static final int ALL = (DOUBLE_QUOTE | SINGLE_QUOTE);

		private final int _type;

		XmlEncoder(String name, int type) {
			super(name);
			_type = type;
		}

		XmlEncoder(int type) {
			_type = type;
		}

		/** {@inheritDoc} */
		@Override
		public final <T extends Appendable> T apply(T buf, CharSequence text)
				throws IOException {
			if (text != null) {
				for (int i = 0, n = text.length(); i < n; ++i) {
					char ch = text.charAt(i);

					switch (ch) {
					case '<':
						buf.append("&lt;");
						break;
					case '>':
						buf.append("&gt;");
						break;
					case '&':
						buf.append("&amp;");
						break;
					case '\"':
						if ((_type & DOUBLE_QUOTE) != 0) {
							buf.append("&#34;");
						} else {
							buf.append(ch);
						}
						break;
					case '\'':
						if ((_type & SINGLE_QUOTE) != 0) {
							buf.append("&#39;");
						} else {
							buf.append(ch);
						}
						break;
					default:
						// in addition to escaping, we also make sure
						// not to output any characters that are
						// invalid according to the XML specification.
						// Some XML parsers will refuse to parse
						// invalid characters. See the <a
						// href="http://www.w3.org/TR/REC-xml/#charsets">XML
						// Specification entry on charsets</a>.

						// [2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] |
						// [#xE000-#xFFFD] | [#x10000-#x10FFFF]

						if (isValidXMLChar(ch)) {
							buf.append(ch);
						} else if (i + 1 < n
								&& Character.isSurrogatePair(ch, text
										.charAt(i + 1))) {
							buf.append(ch).append(text.charAt(++i));
						} else {
							// invalid characters get replaced with a
							// space (for now). This prevents
							// "<scr\0ipt>" from becoming "<script>"
							buf.append(' ');
						}
					}
				}
			}
			return buf;
		}
	}

	/**
	 * Encodes a Uniform Resource Identifier (URI) component by replacing each
	 * instance of certain characters by one, two, or three escape sequences
	 * representing the UTF-8 encoding of the character.
	 * 
	 * (Javadoc description from Mozilla.org's description for the JavaScript
	 * method of the same name.)
	 */
	static class EncodeURIComponent extends Encoder {
		/**
		 * Bit masks where the 1 bits represent the characters in a-z, A-Z, 0-9,
		 * and -_.!~*'(). Since the encode deals with bytes, only 4 x 64-bits
		 * (=256) are needed.
		 */
		private static final long[] BITS = new long[] { 0x3ff678200000000L,
				0x47fffffe87fffffeL, 0L, 0L, };

		private String _encoding;

		EncodeURIComponent() {
			super("uri-component");
			_encoding = "UTF-8";
		}

		EncodeURIComponent(String encoding) {
			_encoding = encoding;
		}

		@Override
		public <T extends Appendable> T apply(T buf, CharSequence text)
				throws IOException {
			if (text != null) {
				byte[] bytes = text.toString().getBytes(_encoding);
				for (int i = 0, n = bytes.length; i < n; ++i) {
					char ch = (char) (bytes[i] & 0xff);

					if ((BITS[ch >> 6] & (1L << ch)) != 0) {
						buf.append((char) ch);
					} else {
						buf.append('%').append(HEX[(ch >> 4) & 0xf]).append(
								HEX[ch & 0xf]);
					}
				}
			}

			return buf;
		}
	}

	public final static String encodeForURIComponent(String input) {
		return Encoder.URI_COMPONENT.apply(input);
	}
	
	/**
	 * Encodes a Uniform Resource Identifier (URI) by replacing each instance of
	 * certain characters by one, two, or three escape sequences representing
	 * the UTF-8 encoding of the character.
	 * 
	 * Note that encodeURI by itself cannot form proper HTTP GET and POST
	 * requests, such as for XMLHTTPRequests, because "&", "+", and "=" are not
	 * encoded, which are treated as special characters in GET and POST
	 * requests. encodeURIComponent, however, does encode these characters.
	 * These behaviors are most likely not consistent across browsers.
	 * 
	 * (Javadoc description from Mozilla.org's description for the JavaScript
	 * method of the same name.)
	 */
	static class EncodeURI extends Encoder {
		/**
		 * Bit masks where the 1 bits represent the characters in a-z, A-Z, 0-9,
		 * and ;,/?:@&=+$-_.!~*'()#. Since the encode deals with bytes, only 4 x
		 * 64-bits (=256) are needed.
		 */
		private static final long[] BITS = new long[] { 0xafffffda00000000L,
				0x47fffffe87ffffffL, 0L, 0L, };

		private String _encoding;

		EncodeURI() {
			super("uri");
			_encoding = "UTF-8";
		}

		EncodeURI(String encoding) {
			_encoding = encoding;
		}

		@Override
		public <T extends Appendable> T apply(T buf, CharSequence text)
				throws IOException {
			if (text != null) {
				byte[] bytes = text.toString().getBytes(_encoding);
				for (int i = 0, n = bytes.length; i < n; ++i) {
					char ch = (char) (bytes[i] & 0xff);

					if ((BITS[ch >> 6] & (1L << ch)) != 0) {
						buf.append((char) ch);
					} else {
						buf.append('%').append(HEX[(ch >> 4) & 0xf]).append(
								HEX[ch & 0xf]);
					}
				}
			}

			return buf;
		}
	}
	
	public final static String encodeForURI(String input) {
		return Encoder.URI.apply(input);
	}


	/** The name of the escape */
	private String _name;

	/**
	 * Constructor for singleton escapes provided here. The name of the escape
	 * is used to put this instance into a map.
	 * 
	 * @param name
	 *            the name of the escape
	 */
	private Encoder(String name) {
		_name = name;
		ENUM_MAP.put(name, this);
	}

	/**
	 * Package-private constructor for non-singleton instances. This does not
	 * add values to the singleton map. It also does not allow non-packaged
	 * sub-classes (perhaps to be allowed later).
	 */
	Encoder() {
	}

	/**
	 * Creates an escape for a sequence of escapes. The returned value will
	 * apply each escape in order. For example:
	 * 
	 * <pre>
	 * String output = Encoder.forSequence(JAVASCRIPT, XML).apply(input);
	 * </pre>
	 * 
	 * Is the same as:
	 * 
	 * <pre>
	 * String temp = Encoder.JAVASCRIPT.apply(input);
	 * String output = Encoder.XML.apply(temp);
	 * </pre>
	 * 
	 * It is safe to create a sequence from other sequences. This implementation
	 * will actually optimize out subsequences to inline them.
	 * 
	 * @param types
	 *            a list of escapes. Must not be empty.
	 * @return the sequenced escape
	 * @throws NullPointerExceptoin
	 *             if any type is null.
	 */
	public static Encoder forSequence(Encoder... types) {
		if (types.length == 0) {
			throw new IllegalArgumentException(
					"must specify at least one escape");
		}

		if (types.length == 1) {
			return types[0];
		}

		return new Sequence(types);
	}

	/**
	 * Returns an Encoder for URI components that operates in the specified
	 * character encoding. This should only be needed if the page is encoded in
	 * something other than UTF-8. Otherwise using the URI_COMPONENT constant is
	 * preferred.
	 * 
	 * @param encoding
	 *            the character set encoding name (e.g. "UTF-8", "UTF-16LE",
	 *            etc...)
	 * @return the URI encoding escape
	 * @throws UnsupportedEncodingException
	 *             if the specified encoding is not supported by the JVM.
	 */
	public static Encoder forURIComponent(String encoding)
			throws UnsupportedEncodingException {
		if ("UTF-8".equalsIgnoreCase(encoding)) {
			return URI_COMPONENT;
		} else {
			// verify that encoding exists. This will throw an
			// UnsupportedEncodingException.
			"".getBytes(encoding);

			return new EncodeURIComponent(encoding);
		}
	}

	/**
	 * Returns an Encoder for URI that operates in the specified character
	 * encoding. This should only be needed if the page is encoded in something
	 * other than UTF-8. Otherwise using the URI constant is preferred.
	 * 
	 * @param encoding
	 *            the character set encoding name (e.g. "UTF-8", "UTF-16LE",
	 *            etc...)
	 * @return the URI encoding escape
	 * @throws UnsupportedEncodingException
	 *             if the specified encoding is not supported by the JVM.
	 */
	public static Encoder forURI(String encoding)
			throws UnsupportedEncodingException {
		if ("UTF-8".equalsIgnoreCase(encoding)) {
			return URI;
		} else {
			// verify that encoding exists. This will throw an
			// UnsupportedEncodingException.
			"".getBytes(encoding);

			return new EncodeURI(encoding);
		}
	}

	/**
	 * Looks up and returns a standard escape type for a given name.
	 * 
	 * @param name
	 *            the name of the escape to look up
	 * @return the Encoder for the given name or null if not found
	 */
	public static Encoder forName(String name) {
		return ENUM_MAP.get(name);
	}

	/**
	 * Looks up and returns a standard escape type for a given name.
	 * 
	 * @param name
	 *            the name of the escape to look up
	 * @param fallback
	 *            the escape type to fall back to if the given name does not
	 *            specify a valid escape type.
	 * @return the Encoder for the given name or the fallback
	 */
	public static Encoder forName(String name, Encoder fallback) {
		Encoder type = ENUM_MAP.get(name);
		return type != null ? type : fallback;
	}

	/**
	 * Applies the escape on the given text, writing to the given buffer.
	 * 
	 * @param buf
	 *            where to output
	 * @param text
	 *            the input to escape
	 * @return The <code>buf</code> argument
	 * @throws IOException
	 *             from the underlying Appendable
	 */
	public abstract <T extends Appendable> T apply(T buf, CharSequence text)
			throws IOException;

	/**
	 * Applies the escape on the given text, writing to the given buffer. This
	 * simply calls out to the Appendable version and hides the IOException
	 * which will never occur.
	 * 
	 * @param buf
	 *            where to output
	 * @param text
	 *            the input to escape
	 * @return The <code>buf</code> argument
	 */
	public final StringBuilder apply(StringBuilder buf, CharSequence text) {
		try {
			apply((Appendable) buf, text);
			return buf;
		} catch (IOException e) {
			throw new UnsupportedOperationException("Unexpected IOException", e);
		}
	}

	/**
	 * Applies the escape on the given text, writing to the given buffer. This
	 * simply calls out to the Appendable version and hides the IOException
	 * which will never occur.
	 * 
	 * @param buf
	 *            where to output
	 * @param text
	 *            the input to escape
	 * @return The <code>buf</code> argument
	 */
	public final StringBuffer apply(StringBuffer buf, CharSequence text) {
		try {
			apply((Appendable) buf, text);
			return buf;
		} catch (IOException e) {
			throw new UnsupportedOperationException("Unexpected IOException", e);
		}
	}

	/**
	 * Applies the escape on the given text, writing to the given buffer. This
	 * simply calls out to the Appendable version and hides the IOException
	 * which will never occur.
	 * 
	 * @param out
	 *            where to output
	 * @param text
	 *            the input to escape
	 * @return The <code>buf</code> argument
	 */
	public final PrintWriter apply(PrintWriter out, CharSequence text) {
		try {
			apply((Appendable) out, text);
			return out;
		} catch (IOException e) {
			throw new UnsupportedOperationException("Unexpected IOException", e);
		}
	}

	/**
	 * Applies the escape to the given input and returns the result as a string.
	 * This is pretty much the same as:
	 * 
	 * <pre>
	 * escape.apply(new StringBuilder(), input).toString();
	 * </pre>
	 * 
	 * Note: <code>null<code> input always results in an empty string
     * result.
	 * 
	 * @param text
	 *            the text to escape
	 * @return the escaped text
	 */
	public final String apply(CharSequence text) {
		if (text == null) {
			return "";
		}

		int n = text.length();

		n += n >> 1;

		return apply(new StringBuilder(n), text).toString();
	}

	/**
	 * Applies the escape to a given object by first converting it to a String
	 * using the objects .toString method.
	 * 
	 * @param buf
	 *            where to output
	 * @param text
	 *            the input to escape
	 * @return The <code>buf</code> argument
	 * @throws IOException
	 *             from the underlying Appendable
	 */
	public final <T extends Appendable> T apply(T buf, Object obj)
			throws IOException {
		return apply(buf, String.valueOf(obj));
	}

	/**
	 * Applies the escape to a given object by first converting it to a String
	 * using the objects .toString method. This version does not throw an
	 * IOException.
	 * 
	 * @param buf
	 *            where to output
	 * @param text
	 *            the input to escape
	 * @return The <code>buf</code> argument
	 * @throws IOException
	 *             from the underlying Appendable
	 */
	public final PrintWriter apply(PrintWriter out, Object obj) {
		return apply(out, String.valueOf(obj));
	}

	/**
	 * Applies the escape to a given object by first converting it to a String
	 * using the objects .toString method.
	 * 
	 * @param obj
	 *            the input to escape
	 * @return the string value of obj escaped.
	 */
	public final String apply(Object obj) {
		return apply(String.valueOf(obj));
	}

	/**
	 * Returns a writer that will filter all writes through the encoding and
	 * pass on to the writer argument.
	 * 
	 * @param out
	 *            the writer to wrap
	 * @return a filtered encoding writer wrapper
	 */
	public final Writer wrap(Writer out) {
		return new EncoderWriter(this, out);
	}

	/**
	 * Returns the name of the escape.
	 * 
	 * @return the name of the escape.
	 */
	public final String toString() {
		return _name;
	}

} // Encoder
