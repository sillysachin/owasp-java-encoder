Contextual Output Encoding is a computer programming technique necessary to stop _Cross Site Scripting_. This project is a Java 1.5+ simple-to-use drop-in high-performance encoder class with little baggage.

For more information on how to use this project, please see [https://www.owasp.org/index.php/OWASP\_Java\_Encoder\_Project#tab=Use\_the\_Java\_Encoder\_Project](https://www.owasp.org/index.php/OWASP_Java_Encoder_Project#tab=Use_the_Java_Encoder_Project)

## Start using the OWASP Java Encoders ##

You can download a JAR at http://search.maven.org/remotecontent?filepath=org/owasp/encoder/encoder/1.1.1/encoder-1.1.1.jar.

JSP tags and functions are available in [http://search.maven.org/remotecontent?filepath=org/owasp/encoder/encoder-jsp/1.1.1/encoder-jsp-1.1.1.jar](http://search.maven.org/remotecontent?filepath=org/owasp/encoder/encoder-jsp/1.1.1/encoder-jsp-1.1.1.jar).  This jar requires the core library.

The jars are also available in Maven:

```
<dependency>
	<groupId>org.owasp.encoder</groupId>
	<artifactId>encoder</artifactId>
	<version>1.1.1</version>
</dependency>
```
```
<dependency>
	<groupId>org.owasp.encoder</groupId>
	<artifactId>encoder-jsp</artifactId>
	<version>1.1.1</version>
</dependency>
```

## Quick Overview ##

The OWASP Java Encoder library is intended for quick contextual encoding with very little overhead, either in performance or usage.  To get started, simply add the [encoder-1.1.1.jar](http://search.maven.org/remotecontent?filepath=org/owasp/encoder/encoder/1.1.1/encoder-1.1.1.jar), `import org.owasp.encoder.Encode` and start using.

Example usage:
```
    PrintWriter out = ....;
    out.println("<textarea>"+Encode.forHtml(userData)+"</textarea>");    
```

Please look at the [javadoc for Encode](http://owasp-java-encoder.googlecode.com/svn/tags/1.1/core/apidocs/org/owasp/encoder/Encode.html) to see the variety of contexts for which you can encode.

If you want to try it out or see it in action, head over to "[Can You XSS This? (.com)](http://canyouxssthis.com/)" and hit it with your best XSS attack vectors!

Happy Encoding!

## News ##

### 2014-03-31 - Documentation updated ###

Please visit [https://www.owasp.org/index.php/OWASP\_Java\_Encoder\_Project#tab=Use\_the\_Java\_Encoder\_Project](https://www.owasp.org/index.php/OWASP_Java_Encoder_Project#tab=Use_the_Java_Encoder_Project) to see detailed documentation and examples on each API use!

### 2014-01-30 - Version 1.1.1 released ###

We're happy to announce that version 1.1.1 has been released.  Along with a important bug fix, we added ESAPI integration to replace the legacy ESAPI encoders with the OWASP Java Encoder.

### 2013-02-14 - Version 1.1 released ###

We're happy to announce that version 1.1 has been released.  Along with a few minor encoding enhancements, we improved performance, and added a JSP tag and function library.