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

import java.io.IOException;
import java.io.Writer;
import java.nio.CharBuffer;
import java.nio.charset.CoderResult;

/**
 * Encode -- fluent interface for contextual encoding.  Example usage in a JSP:
 *
 * <pre>
 *     &lt;input value="&lt;%=Encode.forHtml(value)%>" />
 * </pre>
 *
 * <p>There are two versions of each contextual encoding method.  The first
 * takes a {@code String} argument and returns the encoded version as a
 * {@code String}.  The second version writes the encoded version directly
 * to a {@code Writer}.</p>
 *
 * <p>Please make sure to read and understand the context that the method encodes
 * for.  Encoding for the incorrect context will likely lead to exposing a
 * cross-site scripting vulnerability.</p>
 *
 * @author Jeff Ichnowski
 */
public final class Encode {
    /** No instances. */
    private Encode() {}

    /**
     * A ThreadLocal buffer used for performing the encoding.  The buffer
     * can significantly reduce the amount of allocations required to
     * perform encoding, but may not be needed if GC performance becomes
     * a non-issue.
     */
    private static ThreadLocal<Buffer> _localBuffer = new ThreadLocal<Buffer>() {
        @Override
        protected Buffer initialValue() {
            return new Buffer();
        }
    };

    /**
     * <p>Encodes for (X)HTML text content and text attributes.  Since
     * this method encodes for both contexts, it may be slightly less
     * efficient to use this method over the methods targeted towards
     * the specific contexts ({@link #forHtmlAttribute(String)} and
     * {@link #forHtmlContent(String)}.  In general this method should
     * be preferred unless you are really concerned with saving a few
     * bytes or are writing a framework that utilizes this
     * package.</p>
     *
     * <h5>Example JSP Usage:</h5>
     * <pre>
     *     &lt;div>&lt;%=Encode.forHtml(unsafeData)%>&lt;/div>
     *
     *     &lt;input value="&lt;%=Encode.forHtml(unsafeData)%>" />
     * </pre>
     *
     * <h5>Encoding Description</h5>
     * <table cellspacing="1" cellpadding="1" border="0">
     *   <thead>
     *     <tr bgcolor="#ccf">
     *       <th align="left" colspan="2">Input Character</th>
     *       <th align="left">Encoded Result</th>
     *       <th align="left">Notes</th>
     *     </tr>
     *   </thead>
     *   <tbody>
     *     <tr>
     *       <td>U+0026</td>
     *       <td><code>&amp;</code></td>
     *       <td><code>&amp;amp;</code></td>
     *       <td></td>
     *     </tr>
     *     <tr>
     *       <td>U+003C</td>
     *       <td><code>&lt;</code></td>
     *       <td><code>&amp;lt;</code></td>
     *       <td></td>
     *     </tr>
     *     <tr>
     *       <td>U+003E</td>
     *       <td><code>&gt;</code></td>
     *       <td><code>&amp;gt;</code></td>
     *       <td>This escape is not strictly required, but is
     *       included for maximum compatibility.</td>
     *     </tr>
     *     <tr>
     *       <td>U+0022</td>
     *       <td><code>"</code></td>
     *       <td><code>&amp;#34;</code></td>
     *       <td>"&amp;quot;" would also be valid.  The numeric
     *       version is used since it is shorter.</td>
     *     </tr>
     *     <tr>
     *       <td>U+0027</td>
     *       <td><code>'</code></td>
     *       <td><code>&amp;#39;</code></td>
     *       <td></td>
     *     </tr>
     *   </tbody>
     * </table>
     *
     * <p>In addition to the above translation, only <a
     * href="http://www.w3.org/TR/REC-xml/#charsets">characters that
     * are valid according to the XML specification</a> are allowed
     * through.  Invalid characters are replaced with a single space
     * character (U+0020).  This additional step enables XHTML
     * compliance when utilizing this method.</p>
     *
     * @param input the data to encode
     * @return the data encoded for html.
     */
    public static String forHtml(String input) {
        return forXml(input);
    }

    /**
     * See {@link #forHtml(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forHtml(Writer out, String input) throws IOException {
        forXml(out, input);
    }

    /**
     * <p>This method encodes for HTML text content.  It does not escape
     * quotation characters and is thus unsafe for use with
     * HTML attributes.  Use either forHtml or forHtmlAttribute for those
     * methods.</p>
     *
     * <pre>
     *     &lt;div>&lt;%=Encode.forHtmlContent(unsafeData)%>&lt;/div>
     * </pre>
     *
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forHtmlContent(String input) {
        return forXmlContent(input);
    }

    /**
     * See {@link #forHtmlContent(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forHtmlContent(Writer out, String input)
        throws IOException
    {
        forXmlContent(out, input);
    }

    /**
     * <p>This method encodes for HTML text attributes.</p>
     *
     * <pre>
     *     &lt;div>&lt;%=Encode.forHtml(unsafeData)%>&lt;/div>
     * </pre>
     *
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forHtmlAttribute(String input) {
        return forXmlAttribute(input);
    }

    /**
     * See {@link #forHtmlAttribute(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forHtmlAttribute(Writer out, String input)
        throws IOException
    {
        forXmlAttribute(out, input);
    }


    /**
     * <p>Encodes for unquoted HTML attribute values.  {@link
     * #forHtml(String)} or {@link #forHtmlAttribute(String)} should
     * usually be preferred over this method as quoted attributes are
     * XHTML compliant.</p>
     *
     * <p>When using this method, the caller is not required to
     * provide quotes around the attribute (since it is encoded for
     * such context).  The caller should make sure that the attribute
     * value does not abut unsafe characters--and thus should usually
     * err on the side of including a space character after the
     * value.</p>
     *
     * <pre>
     *     &lt;input value=&lt;%=Encode.forHtmlUnquotedAttribute(input)%> >
     * </pre>
     *
     * @param input the attribute value to be encoded.
     * @return the attribute value encoded for unquoted attribute
     * context.
     */
    public static String forHtmlUnquotedAttribute(String input) {
        return encode(Encoders.HTML_UNQUOTED_ATTRIBUTE_ENCODER, input);
    }

    /**
     * See {@link #forHtmlUnquotedAttribute(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forHtmlUnquotedAttribute(Writer out, String input)
        throws IOException
    {
        encode(Encoders.HTML_UNQUOTED_ATTRIBUTE_ENCODER, out, input);
    }


    // HTML comment encoding is not currently supported because
    // of the number of vendor-specific sequences that would need
    // to be handled (e.g. "<!--[if IE]-->"

//    public static String forHtmlComment(String input) {
//        // only alphanumeric and space, everything else becomes a space
//
//        // HTML comment context needs to avoid browser extensions
//        // such as "<!--[if IE]-->"
//        throw new UnsupportedOperationException();
//    }

    /**
     * Encodes for CSS strings.  The context must be surrounded by quotation
     * characters.  It is safe for use in both style blocks and attributes in
     * HTML.
     *
     * <pre>
     *     &lt;div style="background: url('&lt;=Encode.forCssString(...)%>');">
     *
     *     &lt;style type="text/css">
     *         background: url('&lt;%=Encode.forCssString(...)%>');
     *     &lt;/style>
     * </pre>
     *
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forCssString(String input) {
        // need to watch out for CSS expressions
        return encode(Encoders.CSS_STRING_ENCODER, input);
    }

    /**
     * See {@link #forCssString(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forCssString(Writer out, String input)
        throws IOException
    {
        encode(Encoders.CSS_STRING_ENCODER, out, input);
    }

    /**
     * Encodes for CSS URL contexts.  The context must be surrounded by {@code "url("}
     * and {@code ")"}.  It is safe for use in both style blocks and attributes in HTML.
     * Note: this does not do any checking on the quality or safety of the URL
     * itself.  The caller should insure that the URL is safe for embedding
     * (e.g. input validation) by other means.
     *
     * <pre>
     *     &lt;div style="background:url(&lt;=Encode.forCssUrl(...)%>);">
     *
     *     &lt;style type="text/css">
     *         background: url(&lt;%=Encode.forCssUrl(...)%>);
     *     &lt;/style>
     * </pre>
     *
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forCssUrl(String input) {
        return encode(Encoders.CSS_URL_ENCODER, input);
    }

    /**
     * See {@link #forCssUrl(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forCssUrl(Writer out, String input)
        throws IOException
    {
        encode(Encoders.CSS_URL_ENCODER, out, input);
    }

    /**
     * Performs percent-encoding of a URL according to RFC 3986.  The provided
     * URL is assumed to a valid URL.  This method does not do any checking on
     * the quality or safety of the URL itself.  In many applications it may
     * be better to use {@link java.net.URI} instead.  Note: this is a
     * particularly dangerous context to put untrusted content in, as for
     * example a "javascript:" URL provided by a malicious user would be
     * "properly" escaped, and still execute.
     *
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forUri(String input) {
        return encode(Encoders.URI_ENCODER, input);
    }

    /**
     * See {@link #forUri(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forUri(Writer out, String input)
        throws IOException
    {
        encode(Encoders.URI_ENCODER, out, input);
    }

    /**
     * Performs percent-encoding for a component of a URI, such as a query
     * parameter name or value, path or query-string.  In particular this
     * method insures that special characters in the component do not get
     * interpreted as part of another component.
     *
     * <pre>
     *     &lt;a href="http://www.owasp.org/&lt;%=Encode.forUriComponent(...)%>?query#fragment">
     *
     *     &lt;a href="/search?value=&lt;%=Encode.forUriComponent(...)%>&order=1#top">
     * </pre>
     *
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forUriComponent(String input) {
        return encode(Encoders.URI_COMPONENT_ENCODER, input);
    }

    /**
     * See {@link #forUriComponent(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forUriComponent(Writer out, String input)
        throws IOException
    {
        encode(Encoders.URI_COMPONENT_ENCODER, out, input);
    }

    /**
     * Encoder for XML and XHTML.
     *
     * @see #forHtml(String) forHtml(string) for general description of context.
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forXml(String input) {
        return encode(Encoders.XML_ENCODER, input);
    }

    /**
     * See {@link #forXml(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forXml(Writer out, String input)
        throws IOException
    {
        encode(Encoders.XML_ENCODER, out, input);
    }

    /**
     * Encoder for XML and XHTML text content.
     *
     * @see #forHtmlContent(String) forHtmlContent(String) for general description of context.
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forXmlContent(String input) {
        return encode(Encoders.XML_CONTENT_ENCODER, input);
    }

    /**
     * See {@link #forXmlContent(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forXmlContent(Writer out, String input)
        throws IOException
    {
        encode(Encoders.XML_CONTENT_ENCODER, out, input);
    }

    /**
     * Encoder for XML and XHTML attribute content.
     *
     * @see #forHtmlAttribute(String) forHtmlAttribute(String) for general description of context.
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forXmlAttribute(String input) {
        return encode(Encoders.XML_ATTRIBUTE_ENCODER, input);
    }

    /**
     * See {@link #forXmlAttribute(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forXmlAttribute(Writer out, String input)
        throws IOException
    {
        encode(Encoders.XML_ATTRIBUTE_ENCODER, out, input);
    }

    /**
     * Encoder for XML comments.  <strong>NOT FOR USE WITH
     * (X)HTML CONTEXTS.</strong>  (X)HTML comments may be interpreted by
     * browsers as something other than a comment, typically in vendor
     * specific extensions (e.g. {@code <--if[IE]-->}).
     * For (X)HTML it is recommend that unsafe content never be included
     * in a comment.
     *
     * <p>The caller must provide the comment start and end sequences.</p>
     *
     * <p>This method replaces all invalid XML characters with spaces,
     * and replaces the "--" sequence (which is invalid in XML comments)
     * with "-~" (hyphen-tilde).  <b>This encoding behavior may change
     * in future releases.</b>  If the comments need to be decoded, the
     * caller will need to come up with their own encode/decode system.</p>
     *
     * <pre>
     *     out.println("&lt;?xml version='1.0'?>");
     *     out.println("&lt;data>");
     *     out.println("&;lt;!-- "+Encode.forXmlComment(comment)+" -->");
     *     out.println("&lt;/data>");
     * </pre>
     *
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forXmlComment(String input) {
        return encode(Encoders.XML_COMMENT_ENCODER, input);
    }

    /**
     * See {@link #forXmlComment(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forXmlComment(Writer out, String input)
        throws IOException
    {
        encode(Encoders.XML_COMMENT_ENCODER, out, input);
    }

    /**
     * Encodes data for an XML CDATA section.  On the chance that the input
     * contains a terminating {@code "]]>"}, it will be replaced by
     * {@code "]]>]]<![CDATA[>"}.
     * As with all XML contexts, characters that are invalid according to the
     * XML specification will be replaced by a space character.   Caller must
     * provide the CDATA section boundaries.
     *
     * <pre>
     *     &lt;xml-data>&lt;![CDATA[&lt;%=Encode.forCDATA(...)%>]]>&lt;/xml-data>
     * </pre>
     *
     * @param input the input to encode
     * @return the encoded result
     */
    public static String forCDATA(String input) {
        return encode(Encoders.CDATA_ENCODER, input);
    }

    /**
     * See {@link #forCDATA(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forCDATA(Writer out, String input)
        throws IOException
    {
        encode(Encoders.CDATA_ENCODER, out, input);
    }

    /**
     * Encodes for a Java string.  This method will use "\b", "\t", "\r", "\f",
     * "\n", "\"", "\'", "\\", octal and unicode escapes.  Valid surrogate
     * pairing is not checked.   The caller must provide the enclosing quotation
     * characters.  This method is useful for when writing code generators and
     * outputting debug messages.
     *
     * <pre>
     *     out.println("public class Hello {");
     *     out.println("    public static void main(String[] args) {");
     *     out.println("        System.out.println(\"" + Encode.forJava(message) + "\");");
     *     out.println("    }");
     *     out.println("}");
     * </pre>
     *
     * @param input the input to encode
     * @return the input encoded for java strings.
     */
    public static String forJava(String input) {
        return encode(Encoders.JAVA_ENCODER, input);
    }

    /**
     * See {@link #forJava(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forJava(Writer out, String input)
        throws IOException
    {
        encode(Encoders.JAVA_ENCODER, out, input);
    }

    /**
     * <p>Encodes for a JavaScript string.  It is safe for use in HTML
     * script attributes (such as {@code onclick}), script
     * blocks, JSON files, and JavaScript source.  The caller MUST
     * provide the surrounding quotation characters for the string.
     * Since this performs additional encoding so it can work in all
     * of the JavaScript contexts listed, it may be slightly less
     * efficient then using one of the methods targetted to a specific
     * JavaScript context ({@link #forJavaScriptAttribute(String)},
     * {@link #forJavaScriptBlock}, {@link #forJavaScriptSource}).
     * Unless you are interested in saving a few bytes of output or
     * are writing a framework on top of this library, it is recommend
     * that you use this method over the others.</p>
     *
     * <h5>Example JSP Usage:</h5>
     * <pre>
     *    &lt;button onclick="alert('&lt;%=Encode.forJavaScript(data)%>');">
     *    &lt;script type="text/javascript">
     *        var data = "&lt;%=Encode.forJavaScript(data)%>";
     *    &lt;/script>
     * </pre>
     *
     * <h5>Encoding Description</h5>
     * <table cellspacing="1" cellpadding="1" border="0">
     *   <thead>
     *     <tr bgcolor="#ccf">
     *       <th align="left" colspan="2">Input Character</th>
     *       <th align="left">Encoded Result</th>
     *       <th align="left">Notes</th>
     *     </tr>
     *   </thead>
     *   <tbody>
     *     <tr>
     *       <td>U+0008</td><td><i>BS</i></td>
     *       <td><code>\b</code></td>
     *       <td>Backspace character</td>
     *     </tr>
     *     <tr>
     *       <td>U+0009</td><td><i>HT</i></td>
     *       <td><code>\t</code></td>
     *       <td>Horizontal tab character</td>
     *     </tr>
     *     <tr>
     *       <td>U+000A</td><td><i>LF</i></td>
     *       <td><code>\n</code></td>
     *       <td>Line feed character</td>
     *     </tr>
     *     <tr>
     *       <td>U+000C</td><td><i>FF</i></td>
     *       <td><code>\f</code></td>
     *       <td>Form feed character</td>
     *     </tr>
     *     <tr>
     *       <td>U+000D</td><td><i>CR</i></td>
     *       <td><code>\r</code></td>
     *       <td>Carriage return character</td>
     *     </tr>
     *     <tr>
     *       <td>U+0022</td><td><code>"</code></td>
     *       <td><code>\x22</code></td>
     *       <td>The encoding <code>\"</code> is not used here because
     *       it is not safe for use in HTML attributes.  (In HTML
     *       attributes, it would also be correct to use
     *       "\&amp;quot;".)</td>
     *     </tr>
     *     <tr>
     *       <td>U+0026</td><td><code>&</code></td>
     *       <td><code>\x26</code></td>
     *       <td>Ampersand character</td>
     *     </tr>
     *     <tr>
     *       <td>U+0027</td><td><code>'</code></td>
     *       <td><code>\x27</code></td>
     *       <td>The encoding <code>\'</code> is not used here because
     *       it is not safe for use in HTML attributes.  (In HTML
     *       attributes, it would also be correct to use
     *       "\&amp;#39;".)</td>
     *     </tr>
     *     <tr>
     *       <td>U+002F</td><td><code>/</code></td>
     *       <td><code>\/</code></td>
     *       <td>This encoding is used to avoid an input sequence
     *       "&lt;/" from prematurely terminating a &lt;/script>
     *       block.</td>
     *     </tr>
     *     <tr>
     *       <td>U+005C</td><td><code>\</code></td>
     *       <td><code>\\</code></td>
     *       <td></td>
     *     </tr>
     *     <tr>
     *       <td nowrap="nowrap" colspan="2">U+0000 to U+001F</td>
     *       <td><code>\x##</code></td>
     *       <td>Hexadecimal encoding is used for characters in this
     *       range that were not already mentioned in above.</td>
     *     </tr>
     *   </tbody>
     * </table>
     *
     * @param input the input string to encode
     * @return the input encoded for JavaScript
     * @see #forJavaScriptAttribute(String)
     * @see #forJavaScriptBlock(String)
     */
    public static String forJavaScript(String input) {
        return encode(Encoders.JAVASCRIPT_ENCODER, input);
    }

    /**
     * See {@link #forJavaScript(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forJavaScript(Writer out, String input)
        throws IOException
    {
        encode(Encoders.JAVASCRIPT_ENCODER, out, input);
    }

    /**
     * <p>This method encodes for JavaScript strings contained within
     * HTML script attributes (such as {@code onclick}).  It is
     * NOT safe for use in script blocks.  The caller MUST provide the
     * surrounding quotation characters.  This method performs the
     * same encode as {@link #forJavaScript(String)} with the
     * exception that <code>/</code> is not escaped.</p>
     *
     * <p><strong>Unless you are interested in saving a few bytes of
     * output or are writing a framework on top of this library, it is
     * recommend that you use {@link #forJavaScript(String)} over this
     * method.</strong></p>
     *
     * <h5>Example JSP Usage:</h5>
     * <pre>
     *    &lt;button onclick="alert('&lt;%=Encode.forJavaScriptAttribute(data)%>');">
     * </pre>
     *
     * @param input the input string to encode
     * @return the input encoded for JavaScript
     * @see #forJavaScript(String)
     * @see #forJavaScriptBlock(String)
     */
    public static String forJavaScriptAttribute(String input) {
        return encode(Encoders.JAVASCRIPT_ATTRIBUTE_ENCODER, input);
    }

    /**
     * See {@link #forJavaScriptAttribute(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forJavaScriptAttribute(Writer out, String input)
        throws IOException
    {
        encode(Encoders.JAVASCRIPT_ATTRIBUTE_ENCODER, out, input);
    }

    /**
     * <p>This method encodes for JavaScript strings contained within
     * HTML script blocks.  It is NOT safe for use in script
     * attributes (such as <code>onclick</code>).  The caller must
     * provide the surrounding quotation characters.  This method
     * performs the same encode as {@link #forJavaScript(String)} with
     * the exception that <code>"</code> and <code>'</code> are
     * encoded as <code>\"</code> and <code>\'</code>
     * respectively.</p>
     *
     * <p><strong>Unless you are interested in saving a few bytes of
     * output or are writing a framework on top of this library, it is
     * recommend that you use {@link #forJavaScript(String)} over this
     * method.</strong></p>
     *
     * <h5>Example JSP Usage:</h5>
     * <pre>
     *    &lt;script type="text/javascript">
     *        var data = "&lt;%=Encode.forJavaScriptBlock(data)%>";
     *    &lt;/script>
     * </pre>
     *
     * @param input the input string to encode
     * @return the input encoded for JavaScript
     * @see #forJavaScript(String)
     * @see #forJavaScriptAttribute(String)
     */
    public static String forJavaScriptBlock(String input) {
        return encode(Encoders.JAVASCRIPT_BLOCK_ENCODER, input);
    }

    /**
     * See {@link #forJavaScriptBlock(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forJavaScriptBlock(Writer out, String input)
        throws IOException
    {
        encode(Encoders.JAVASCRIPT_BLOCK_ENCODER, out, input);
    }

    /**
     * <p>This method encodes for JavaScript strings contained within
     * a JavaScript or JSON file.  <strong>This method is NOT safe for
     * use in ANY context embedded in HTML.</strong> The caller must
     * provide the surrounding quotation characters.  This method
     * performs the same encode as {@link #forJavaScript(String)} with
     * the exception that <code>/</code> and <code>&amp;</code> are not
     * escaped and <code>"</code> and <code>'</code> are encoded as
     * <code>\"</code> and <code>\'</code> respectively.</p>
     *
     * <p><strong>Unless you are interested in saving a few bytes of
     * output or are writing a framework on top of this library, it is
     * recommend that you use {@link #forJavaScript(String)} over this
     * method.</strong></p>
     *
     * <h5>Example JSP Usage:</h5>
     * This example is serving up JavaScript source directly:
     * <pre>
     *    &lt;%@page contentType="text/javascript; charset=UTF-8"%>
     *    var data = "&lt;%=Encode.forJavaScriptSource(data)%>";
     * </pre>
     *
     * This example is serving up JSON data (users of this use-case
     * are encouraged to read up on "JSON Hijacking"):
     * <pre>
     *    &lt;%@page contentType="application/json; charset=UTF-8"%>
     *    &lt;% myapp.jsonHijackingPreventionMeasure(); %>
     *    {"data":"&lt;%=Encode.forJavaScriptSource(data)%>"}
     * </pre>
     *
     * @param input the input string to encode
     * @return the input encoded for JavaScript
     * @see #forJavaScript(String)
     * @see #forJavaScriptAttribute(String)
     * @see #forJavaScriptBlock(String)
     */
    public static String forJavaScriptSource(String input) {
        return encode(Encoders.JAVASCRIPT_SOURCE_ENCODER, input);
    }

    /**
     * See {@link #forJavaScriptSource(String)} for description of encoding.  This
     * version writes directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param input the input string to encode
     * @throws IOException if thrown by writer
     */
    public static void forJavaScriptSource(Writer out, String input)
        throws IOException
    {
        encode(Encoders.JAVASCRIPT_SOURCE_ENCODER, out, input);
    }

    // Additional?
    // MySQL
    // PostreSQL
    // Oracle
    // ...

    /**
     * Core encoding loop shared by public methods.  It first uses the
     * encoder to scan the input for characters that need encoding.  If
     * no characters require encoding, the input string is returned.
     * Otherwise a thread-local buffer is used to encode the remainder
     * of the input.
     *
     * @param encoder the encoder to use
     * @param str the string to encode
     * @return the input string encoded with the provided encoder.
     */
    static String encode(Encoder encoder, String str) {
        if (str == null) {
            // consistent with String.valueOf(...) use "null" for null.
            str = "null";
        }

        // quick pass--see if we need to actually encode anything, if not
        // return the value unchanged.
        final int n = str.length();
        int j = encoder.firstEncodedOffset(str, 0, n);

        if (j == n) {
            return str;
        }

        // otherwise, we need to encode.  We use a thread-local buffer to avoid
        // excessive memory allocation for these calls.  Note: this means that
        // an encoder implementation must NEVER call this method internally.
        return _localBuffer.get().encode(encoder, str, j);
    }

    /**
     * Core encoding loop shared by public methods.  It first uses the
     * encoder to scan the input for characters that need encoding.  If no
     * characters require encoding, the input string is written directly to
     * the writer.  Otherwise a thread-local buffer is used to encode the
     * remainder of the input to the buffers.  This version saves a wrapping
     * in an String.
     *
     * @param encoder the encoder to use
     * @param out the writer for the encoded output
     * @param str the string to encode
     * @throws IOException if thrown by the writer
     */
    static void encode(Encoder encoder, Writer out, String str)
        throws IOException
    {
        if (str == null) {
            // consistent with String.valueOf(...) use "null" for null.
            str = "null";
        }

        // quick pass--see if we need to actually encode anything, if not
        // return the value unchanged.
        final int n = str.length();
        int j = encoder.firstEncodedOffset(str, 0, n);

        if (j == n) {
            out.write(str);
            return;
        }

        // otherwise, we need to encode.  We use a thread-local buffer to avoid
        // excessive memory allocation for these calls.  Note: this means that
        // an encoder implementation must NEVER call this method internally.
        _localBuffer.get().encode(encoder, out, str, j);
    }

    /**
     * A buffer used for encoding.  Stored as a thread-local to avoid repeated
     * allocation.
     */
    static class Buffer {
        /**
         * Input buffer size, used to extract a copy of the input
         * from a string and then send to the encoder.
         */
        static final int INPUT_BUFFER_SIZE = 1024;
        /**
         * Output buffer size used to store the encoded output before
         * wrapping in a string.
         */
        static final int OUTPUT_BUFFER_SIZE = INPUT_BUFFER_SIZE * 2;

        /**
         * The input buffer.  A heap-allocated, array-backed buffer of
         * INPUT_BUFFER_SIZE used for holding the characters to encode.
         */
        final CharBuffer _input = CharBuffer.allocate(INPUT_BUFFER_SIZE);
        /**
         * The output buffer.  A heap-allocated, array-backed buffer of
         * OUTPUT_BUFFER_SIZE used for holding the encoded output.
         */
        final CharBuffer _output = CharBuffer.allocate(OUTPUT_BUFFER_SIZE);

        /**
         * The core String encoding routine of this class.  It uses the input
         * and output buffers to allow the encoders to work in reuse arrays.
         * When the input and/or output exceeds the capacity of the reused
         * arrays, temporary ones are allocated and then discarded after
         * the encode is done.
         *
         * @param encoder the encoder to use
         * @param str the string to encode
         * @param j the offset in {@code str} to start encoding
         * @return the encoded result
         */
        String encode(Encoder encoder, String str, int j) {
            final int n = str.length();
            final int remaining = n - j;

            if (remaining <= INPUT_BUFFER_SIZE) {
                // the remaining input to encode fits completely in the pre-
                // allocated buffer.
                str.getChars(0, j, _output.array(), 0);
                str.getChars(j, n, _input.array(), 0);

                _input.limit(remaining).position(0);
                _output.clear().position(j);

                CoderResult cr = encoder.encodeArrays(_input, _output, true);
                if (cr.isUnderflow()) {
                    return new String(_output.array(), 0, _output.position());
                }

                // else, it's an overflow, we need to use a new output buffer
                // we'll allocate this buffer to be the exact size of the worst
                // case, guaranteeing a second overflow would not be possible.
                CharBuffer tmp = CharBuffer.allocate(
                    _output.position() +
                    encoder.maxEncodedLength(_input.remaining()));

                // copy over everything that has been encoded so far
                tmp.put(_output.array(), 0, _output.position());

                cr = encoder.encodeArrays(_input, tmp, true);
                if (cr.isOverflow()) {
                    throw new AssertionError("unexpected result from encoder");
                }

                return new String(tmp.array(), 0, tmp.position());
            } else {
                // the input it too large for our pre-allocated buffers
                // we'll use a temporary direct heap allocation
                final int m = j + encoder.maxEncodedLength(remaining);
                CharBuffer buffer = CharBuffer.allocate(m);
                str.getChars(0, j, buffer.array(), 0);
                str.getChars(j, n, buffer.array(), m - remaining);

                CharBuffer input = buffer.duplicate();
                input.limit(m).position(m-remaining);
                buffer.position(j);

                CoderResult cr = encoder.encodeArrays(input, buffer, true);

                if (cr.isOverflow()) {
                    throw new AssertionError("unexpected result from encoder");
                }

                return new String(buffer.array(), 0, buffer.position());
            }
        }

        /**
         * The core Writer encoding routing of this class.  It uses the
         * input and output buffers to allow the encoders to reuse arrays.
         * Unlike the string version, this method will never allocate more
         * memory, instead encoding is done in batches and flushed to the
         * writer in batches as large as possible.
         *
         * @param encoder the encoder to use
         * @param out where to write the encoded output
         * @param str the string to encode
         * @param j the position in the string at which the first character
         * needs encoding.
         * @throws IOException if thrown by the writer.
         */
        void encode(Encoder encoder, Writer out, String str, int j)
            throws IOException
        {
            out.write(str, 0, j);

            final int n = str.length();

            _input.clear();
            _output.clear();

            final char[] inputArray = _input.array();
            final char[] outputArray = _output.array();

            for (;;) {
                final int remainingInput = n - j;
                final int startPosition = _input.position();
                final int batchSize = Math.min(remainingInput, _input.remaining());
                str.getChars(j, j+batchSize, inputArray, startPosition);

                _input.limit(startPosition + batchSize);


                for (;;) {
                    CoderResult cr = encoder.encodeArrays(
                        _input, _output, batchSize == remainingInput);

                    if (cr.isUnderflow()) {
                        // get next input batch
                        break;
                    }

                    // else, output buffer full, flush and continue.
                    out.write(outputArray, 0, _output.position());
                    _output.clear();
                }

                j += _input.position() - startPosition;

                if (j == n) {
                    // done.  flush remaining output buffer and return
                    out.write(outputArray, 0, _output.position());
                    return;
                }

                _input.compact();
            }
        }
    }
}
