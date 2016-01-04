package org.amex.dpg.JavaCallOut;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import org.globallogic.xmlsec.Encrypter;

import java.io.PrintWriter;
import java.io.StringWriter;

public class SimpleJavaCalloutEncrypt implements Execution{
	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
		try
		{
			String xmlString = Encrypter.encriptXml(messageContext.getMessage().getContent(),"testaio2.pem");
			messageContext.getMessage().setContent(xmlString);
			messageContext.getMessage().setHeader("Content-Type", "application/xml");
			return ExecutionResult.SUCCESS;

		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			String exceptionAsString = sw.toString();			
			messageContext.setVariable("ERROR_MESSAGE", exceptionAsString);
			return ExecutionResult.ABORT;
		}
	}
}