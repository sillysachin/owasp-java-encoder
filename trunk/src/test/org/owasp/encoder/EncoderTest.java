/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.encoder;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.owasp.encoder.Encoder;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;



/**
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public class EncoderTest extends TestCase {

    //private static final char[] EMPTY_CHAR_ARRAY = new char[0];
    //private static final Character LESS_THAN = Character.valueOf('<');
    //private static final Character SINGLE_QUOTE = Character.valueOf('\'');

	
	//from JXT
    public void testEscapeJava() {
        assertEquals("abc", Encoder.JAVA_STRING.apply("abc"));
        assertEquals("\\\"", Encoder.JAVA_STRING.apply("\""));
    }

    public void testEscapeXML() {
        assertEquals("abc", Encoder.XML.apply("abc"));
        assertEquals("&lt;&gt;&amp;&#39;&#34;", Encoder.XML.apply("<>&\'\""));
    }

    public void testEscapeXMLRemoveInvalidChars() {
        // keep valid characters
        assertEquals("A\rB\nC\tD E", Encoder.XML.apply("A\rB\nC\tD E"));

        // invalid characters (non-surrogates)
        assertEquals("A B C", Encoder.XML.apply("A\u0019B\ufffeC"));
        // unmatched surrogate characters
        assertEquals("X Y Z", Encoder.XML.apply("X\uD800Y\uDfffZ"));
        // high-surrogate-at-end
        assertEquals("HS ", Encoder.XML.apply("HS\uDBFF"));

        // check that valid surrogate pairs are let through
        char[] spair = new char[2];
        int n = Character.toChars(0x10000, spair, 0);
        assertEquals(2, n);
        assertEquals(new String(spair), Encoder.XML.apply(new String(spair)));
    }

    public void testEscapeXMLContentRemoveInvalidChars() {
        // keep valid characters
        assertEquals("A\rB\nC\tD E", Encoder.XML_CONTENT.apply("A\rB\nC\tD E"));

        // invalid characters (non-surrogates)
        assertEquals("A B C", Encoder.XML_CONTENT.apply("A\u0019B\ufffeC"));
        // unmatched surrogate characters
        assertEquals("X Y Z", Encoder.XML_CONTENT.apply("X\uD800Y\uDfffZ"));
        // high-surrogate-at-end
        assertEquals("HS ", Encoder.XML_CONTENT.apply("HS\uDBFF"));

        // check that valid surrogate pairs are let through
        char[] spair = new char[2];
        int n = Character.toChars(0x10000, spair, 0);
        assertEquals(2, n);
        assertEquals(new String(spair), Encoder.XML_CONTENT.apply(new String(spair)));
    }

    public void testExceptionMask() {
        Encoder.XML.apply(new StringBuilder(), "abc");
        Encoder.XML.apply(new StringBuffer(), "abc");
        Encoder.XML.apply(new PrintWriter(new StringWriter()), "abc");
    }

    static void checkEncodeURIComponent(String expected, String input) {
        String actual = Encoder.URI_COMPONENT.apply(input);
        assertEquals(expected, actual);
    }

    public void testEncodeURIComponent() throws Exception {
        // Characters that do not get encoded
        checkEncodeURIComponent("abc123xyz890ABC()'*~!._-",
                                "abc123xyz890ABC()'*~!._-");

        // Space and Plus shenanigans
        checkEncodeURIComponent("%20%2b", " +");

        // Characters that would confuse URI parameter processing
        checkEncodeURIComponent("%23%26%25%3d", "#&%=");

        // Unicode characters
        checkEncodeURIComponent("%c2%a0%ef%bc%aa", "\u00a0\uff2a");
    }

    static void checkEncodeURI(String expected, String input) {
        String actual = Encoder.URI.apply(input);
        assertEquals(expected, actual);
    }

    public void testEncodeURI() throws Exception {
        // Characters that do not get encoded
        checkEncodeURI("abc123xyz890ABC()'*~!._-;,/?:@&=+$",
                       "abc123xyz890ABC()'*~!._-;,/?:@&=+$");

        // Space and Plus shenanigans
        checkEncodeURI("%20+", " +");

        // Characters that would confuse URI parameter processing
        checkEncodeURI("#&%25=", "#&%=");

        // Unicode characters
        checkEncodeURI("%c2%a0%ef%bc%aa", "\u00a0\uff2a");
    }

    public void testEncodeXHTML_URI() throws Exception {
        assertEquals(
            "abc&amp;123=%3c%3e%20#",
            Encoder.XHTML_URI.apply("abc&123=<> #"));
    }

    public void testScriptCode() throws Exception {
        assertEquals("ab< /x/.exec(z)",
                     Encoder.SCRIPT_CODE.apply("ab</x/.exec(z)"));
    }

    public void testSequence() throws Exception {
        assertEquals("a=%20&amp;b=%c2%a0",
                     Encoder.XHTML_URI.apply("a= &b=\u00a0"));
    }

    public void testSequenceOfFour() throws Exception {
        final String src = "A\"B\'C\\D&E%F<G>H I\nJ";

        // Note:
        // %5c = '\'
        // %26 = '&'
        // %23 = '#'
        // %3b = ';'
        final String expected =
            "A%5c%5c%26%2334%3b"+
            "B%5c%5c%26%2339%3b"+
            "C%5c%5c%5c%5c"+
            "D%26amp%3b"+
            "E%25"+
            "F%26lt%3b"+
            "G%26gt%3b"+
            "H%20"+
            "I%5c%5cn"+
            "J";

        String verify = Encoder.JAVASCRIPT.apply(src);
        verify = Encoder.XML.apply(verify);
        verify = Encoder.JAVA_STRING.apply(verify);
        verify = Encoder.URI_COMPONENT.apply(verify);

        assertEquals(expected, verify);

        assertEquals(expected,
                     Encoder.forSequence(
                         Encoder.JAVASCRIPT,
                         Encoder.XML,
                         Encoder.JAVA_STRING,
                         Encoder.URI_COMPONENT).apply(src));

    }

    public void testXmlComment() {
        assertEquals("inside -~> outside?", Encoder.XML_COMMENT.apply("inside --> outside?"));
    }

    public void testXmlCommentStart() {
        // Make sure that "-${foo}" can't be exploited
        assertEquals("~> end?", Encoder.XML_COMMENT.apply("-> end?"));
        assertEquals("~-> end?", Encoder.XML_COMMENT.apply("--> end?"));
    }

    public void testXmlCommentEnd() {
        // Make sure that "${foo}>" and "${foo}->" can't be exploited and
        // that "${foo}-->" is always valid
        assertEquals("comment ~", Encoder.XML_COMMENT.apply("comment -"));
        assertEquals("comment -~", Encoder.XML_COMMENT.apply("comment --"));
    }

    public void testXmlCommentRemoveInvalidChars() {
        assertEquals("A B C D E ",
                     Encoder.XML_COMMENT.apply("A\u0019B\ufffeC\uD800D\uDfffE\uDBFF"));
    }
    
    //FROM ESAPI
	
	
    /**
     * Instantiates a new access reference map test.
     * 
     * @param testName
     *            the test name
     */
    public EncoderTest(String testName) {
        super(testName);
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void setUp() throws Exception {
        // none
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void tearDown() throws Exception {
        // none
    }

    /**
     * Suite.
     * 
     * @return the test
     */
    public static Test suite() {
        TestSuite suite = new TestSuite(EncoderTest.class);
        return suite;
    }

	public void testPercentEncode()
	{
        	assertEquals( "%3C", Encoder.encodeForURI("<") );
	}

	public void testHtmlEncode()
	{
        	assertEquals( "test", Encoder.encodeForHTML( "test") );
	}

	public void testJavaScriptEncode()
	{
        	assertEquals( "\\x3C", Encoder.encodeForJavascript("<") );
	}

	public void testCSSEncode()
	{
        // TODO - need CSS encoding functions
		//
		// assertEquals( "\\3c ", cssCodec.encode(EMPTY_CHAR_ARRAY, "<") );
	}

	public void testCSSInvalidCodepointDecode()
	{
		// TODO - need CSS encoding functions
		//
		//assertEquals("\uFFFDg", cssCodec.decode("\\abcdefg") );
	}

	public void testMySQLANSCIEncode()
	{
		// TODO
		//
		//assertEquals( "\'\'", mySQLCodecANSI.encode(EMPTY_CHAR_ARRAY, "\'") );
	}

	public void testMySQLStandardEncode()
	{
		// TODO
		//
		//assertEquals( "\\<", mySQLCodecStandard.encode(EMPTY_CHAR_ARRAY, "<") );
	}

	public void testOracleEncode()
	{
		// TODO - need CSS encoding functions
		//
		//assertEquals( "\'\'", oracleCodec.encode(EMPTY_CHAR_ARRAY, "\'") );
	}

	public void testUnixEncode()
	{
        	//assertEquals( "\\<", unixCodec.encode(EMPTY_CHAR_ARRAY, "<") );
	}

	public void testWindowsEncode()
	{
        	//assertEquals( "^<", windowsCodec.encode(EMPTY_CHAR_ARRAY, "<") );
	}

	
	public void testHtmlEncodeChar()
	{
        	//assertEquals( "&lt;", htmlCodec.encodeCharacter(EMPTY_CHAR_ARRAY, LESS_THAN) );
	}

	public void testHtmlEncodeChar0x100()
	{
		char in = 0x100;
		String inStr = Character.toString(in);
		String expected = "&#x100;";
		String result;

        	result = Encoder.encodeForHTML( in + "");
		// this should be escaped
        	assertFalse(inStr.equals(result));
		// UTF-8 encoded and then percent escaped
        	assertEquals(expected, result);
	}

	public void testHtmlEncodeStr0x100()
	{
		char in = 0x100;
		String inStr = Character.toString(in);
		String expected = "&#x100;";
		String result;

        	result = Encoder.encodeForHTML( inStr);
		// this should be escaped
        	assertFalse(inStr.equals(result));
		// UTF-8 encoded and then percent escaped
        	assertEquals(expected, result);
	}

	public void testPercentEncodeChar()
	{
        	assertEquals( "%3C", Encoder.encodeForURI( "<" ));
	}

	public void testPercentEncodeChar0x100()
	{
		char in = 0x100;
		String inStr = Character.toString(in);
		String expected = "%C4%80";
		String result;

        	result = Encoder.encodeForURI( in + "");
		// this should be escaped
        	assertFalse(inStr.equals(result));
		// UTF-8 encoded and then percent escaped
        	assertEquals(expected, result);
	}

	public void testPercentEncodeStr0x100()
	{
		char in = 0x100;
		String inStr = Character.toString(in);
		String expected = "%C4%80";
		String result;

        	result = Encoder.encodeForURI(inStr);
		// this should be escaped
        	assertFalse(inStr.equals(result));
		// UTF-8 encoded and then percent escaped
        	assertEquals(expected, result);
	}

	public void testJavaScriptEncodeChar()
	{
        	assertEquals( "\\x3C", Encoder.encodeForJavascript("<"));
	}

	public void testJavaScriptEncodeChar0x100()
	{
		char in = 0x100;
		String inStr = Character.toString(in);
		String expected = "\\u0100";
		String result;

        	result = Encoder.encodeForJavascript( in + "");
		// this should be escaped
        	assertFalse(inStr.equals(result));
        	assertEquals(expected,result);
	}

	public void testJavaScriptEncodeStr0x100()
	{
		char in = 0x100;
		String inStr = Character.toString(in);
		String expected = "\\u0100";
		String result;

        	result = Encoder.encodeForJavascript(inStr);
		// this should be escaped
        	assertFalse(inStr.equals(result));
        	assertEquals(expected,result);
	}
        

	public void testCSSEncodeChar()
	{
        //TODO
		//assertEquals( "\\3c ", cssCodec.encodeCharacter(EMPTY_CHAR_ARRAY, LESS_THAN) );
	}

	public void testCSSEncodeChar0x100()
	{
		/*
		 * TODO
		 * 
		 * 
		char in = 0x100;
		String inStr = Character.toString(in);
		String expected = "\\100 ";
		String result;

        result = cssCodec.encodeCharacter(EMPTY_CHAR_ARRAY, in);
		// this should be escaped
        assertFalse(inStr.equals(result));
        assertEquals(expected,result);
        *
        */
	}

	public void testCSSEncodeStr0x100()
	{
		/*
		char in = 0x100;
		String inStr = Character.toString(in);
		String expected = "\\100 ";
		String result;

        	result = cssCodec.encode(EMPTY_CHAR_ARRAY, inStr);
		// this should be escaped
        	assertFalse(inStr.equals(result));
        	assertEquals(expected,result);
        	*/
	}

	/*
	public void testHtmlDecodeDecimalEntities()
	{
        	assertEquals( "test!", htmlCodec.decode("&#116;&#101;&#115;&#116;!") );
	}

	public void testHtmlDecodeHexEntitites()
	{
        	assertEquals( "test!", htmlCodec.decode("&#x74;&#x65;&#x73;&#x74;!") );
	}

	public void testHtmlDecodeInvalidAttribute()
	{
        	assertEquals( "&jeff;", htmlCodec.decode("&jeff;") );
	}

	public void testHtmlDecodeAmp()
	{
		assertEquals("&", htmlCodec.decode("&amp;"));
		assertEquals("&X", htmlCodec.decode("&amp;X"));
		assertEquals("&", htmlCodec.decode("&amp"));
		assertEquals("&X", htmlCodec.decode("&ampX"));
	}

	public void testHtmlDecodeLt()
	{
		assertEquals("<", htmlCodec.decode("&lt;"));
		assertEquals("<X", htmlCodec.decode("&lt;X"));
		assertEquals("<", htmlCodec.decode("&lt"));
		assertEquals("<X", htmlCodec.decode("&ltX"));
	}

	public void testHtmlDecodeSup1()
	{
		assertEquals("\u00B9", htmlCodec.decode("&sup1;"));
		assertEquals("\u00B9X", htmlCodec.decode("&sup1;X"));
		assertEquals("\u00B9", htmlCodec.decode("&sup1"));
		assertEquals("\u00B9X", htmlCodec.decode("&sup1X"));
	}

	public void testHtmlDecodeSup2()
	{
		assertEquals("\u00B2", htmlCodec.decode("&sup2;"));
		assertEquals("\u00B2X", htmlCodec.decode("&sup2;X"));
		assertEquals("\u00B2", htmlCodec.decode("&sup2"));
		assertEquals("\u00B2X", htmlCodec.decode("&sup2X"));
	}

	public void testHtmlDecodeSup3()
	{
		assertEquals("\u00B3", htmlCodec.decode("&sup3;"));
		assertEquals("\u00B3X", htmlCodec.decode("&sup3;X"));
		assertEquals("\u00B3", htmlCodec.decode("&sup3"));
		assertEquals("\u00B3X", htmlCodec.decode("&sup3X"));
	}

	public void testHtmlDecodeSup()
	{
		assertEquals("\u2283", htmlCodec.decode("&sup;"));
		assertEquals("\u2283X", htmlCodec.decode("&sup;X"));
		assertEquals("\u2283", htmlCodec.decode("&sup"));
		assertEquals("\u2283X", htmlCodec.decode("&supX"));
	}

	public void testHtmlDecodeSupe()
	{
		assertEquals("\u2287", htmlCodec.decode("&supe;"));
		assertEquals("\u2287X", htmlCodec.decode("&supe;X"));
		assertEquals("\u2287", htmlCodec.decode("&supe"));
		assertEquals("\u2287X", htmlCodec.decode("&supeX"));
	}

	public void testHtmlDecodePi()
	{
		assertEquals("\u03C0", htmlCodec.decode("&pi;"));
		assertEquals("\u03C0X", htmlCodec.decode("&pi;X"));
		assertEquals("\u03C0", htmlCodec.decode("&pi"));
		assertEquals("\u03C0X", htmlCodec.decode("&piX"));
	}

	public void testHtmlDecodePiv()
	{
		assertEquals("\u03D6", htmlCodec.decode("&piv;"));
		assertEquals("\u03D6X", htmlCodec.decode("&piv;X"));
		assertEquals("\u03D6", htmlCodec.decode("&piv"));
		assertEquals("\u03D6X", htmlCodec.decode("&pivX"));
	}

	public void testHtmlDecodeTheta()
	{
		assertEquals("\u03B8", htmlCodec.decode("&theta;"));
		assertEquals("\u03B8X", htmlCodec.decode("&theta;X"));
		assertEquals("\u03B8", htmlCodec.decode("&theta"));
		assertEquals("\u03B8X", htmlCodec.decode("&thetaX"));
	}

	public void testHtmlDecodeThetasym()
	{
		assertEquals("\u03D1", htmlCodec.decode("&thetasym;"));
		assertEquals("\u03D1X", htmlCodec.decode("&thetasym;X"));
		assertEquals("\u03D1", htmlCodec.decode("&thetasym"));
		assertEquals("\u03D1X", htmlCodec.decode("&thetasymX"));
	}

	public void testPercentDecode()
	{
        	assertEquals( "<", percentCodec.decode("%3c") );
	}

	public void testJavaScriptDecodeBackSlashHex()
	{
        	assertEquals( "<", javaScriptCodec.decode("\\x3c") );
	}
        
	public void testVBScriptDecode()
	{
        	assertEquals( "<", vbScriptCodec.decode("\"<") );
	}

	public void testCSSDecode()
	{
        	assertEquals("<", cssCodec.decode("\\<") );
	}

	public void testCSSDecodeHexNoSpace()
	{
        	assertEquals("Axyz", cssCodec.decode("\\41xyz") );
	}

	public void testCSSDecodeZeroHexNoSpace()
	{
        	assertEquals("Aabc", cssCodec.decode("\\000041abc") );
	}

	public void testCSSDecodeHexSpace()
	{
        	assertEquals("Aabc", cssCodec.decode("\\41 abc") );
	}

	public void testCSSDecodeNL()
	{
        	assertEquals("abcxyz", cssCodec.decode("abc\\\nxyz") );
	}

	public void testCSSDecodeCRNL()
	{
        	assertEquals("abcxyz", cssCodec.decode("abc\\\r\nxyz") );
	}

	public void testMySQLANSIDecode()
	{
        	assertEquals( "\'", mySQLCodecANSI.decode("\'\'") );
	}

	public void testMySQLStandardDecode()
	{
        	assertEquals( "<", mySQLCodecStandard.decode("\\<") );
	}

	public void testOracleDecode()
	{
        	assertEquals( "\'", oracleCodec.decode("\'\'") );
	}

	public void testUnixDecode()
	{
        	assertEquals( "<", unixCodec.decode("\\<") );
	}

        public void testWindowsDecode()
	{
        	assertEquals( "<", windowsCodec.decode("^<") );
	}
	
	public void testHtmlDecodeCharLessThan()
	{
        	assertEquals( LESS_THAN, htmlCodec.decodeCharacter(new PushbackString("&lt;")) );
	}

	public void testPercentDecodeChar()
	{
        	assertEquals( LESS_THAN, percentCodec.decodeCharacter(new PushbackString("%3c") ));
	}

        public void testJavaScriptDecodeCharBackSlashHex()
	{
        	assertEquals( LESS_THAN, javaScriptCodec.decodeCharacter(new PushbackString("\\x3c") ));
	}
        
*/
}
