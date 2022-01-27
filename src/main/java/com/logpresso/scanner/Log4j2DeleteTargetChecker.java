package com.logpresso.scanner;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class Log4j2DeleteTargetChecker implements DeleteTargetChecker {

	private static final String JNDI_LOOKUP_CLASS_PATH = "org/apache/logging/log4j/core/lookup/JndiLookup.class";
	private boolean includeLog4j1;
	private Set<String> targets;

	public Log4j2DeleteTargetChecker(boolean includeLog4j1) {
		this.includeLog4j1 = includeLog4j1;

		targets = new HashSet<String>();
		if (includeLog4j1) {
			targets.add("org/apache/log4j/jdbc/JDBCAppender.class");
			for (String name : Arrays.asList("SocketServer.class", "JMSAppender.class", "SMTPAppender$1.class",
					"SMTPAppender.class", "JMSSink.class"))
				targets.add("org/apache/log4j/net/" + name);
		}

		targets.add(JNDI_LOOKUP_CLASS_PATH);

	}

	@Override
	public boolean isTarget(String entryPath) {
		if (targets.contains(entryPath))
			return true;

		return includeLog4j1 && entryPath.startsWith("org/apache/log4j/chainsaw/");
	}

}
