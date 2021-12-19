package com.logpresso.scanner;

public class DetectResult {
	private boolean vulnerable = false;
	private boolean mitigated = false;
	private boolean potentiallyVulnerableLog4j2 = false;
	private boolean potentiallyVulnerableLog4j1 = false;
	private boolean potentiallyVulnerableLogback = false;
	private boolean nestedJar = false;

	public void merge(DetectResult result) {
		vulnerable |= result.isVulnerable();
		mitigated |= result.isMitigated();
		potentiallyVulnerableLog4j1 |= result.isPotentiallyVulnerableLog4j1();
		potentiallyVulnerableLog4j2 |= result.isPotentiallyVulnerableLog4j2();
		potentiallyVulnerableLogback |= result.isPotentiallyVulnerableLogback();
		nestedJar = true;
	}

	public boolean isVulnerable() {
		return vulnerable;
	}

	public void setVulnerable() {
		this.vulnerable = true;
	}

	public boolean isMitigated() {
		return mitigated;
	}

	public void setMitigated() {
		this.mitigated = true;
	}

	public boolean isPotentiallyVulnerableLog4j2() {
		return potentiallyVulnerableLog4j2;
	}

	public void setPotentiallyVulnerableLog4j2() {
		this.potentiallyVulnerableLog4j2 = true;
	}

	public boolean isPotentiallyVulnerableLog4j1() {
		return potentiallyVulnerableLog4j1;
	}

	public void setPotentiallyVulnerableLog4j1() {
		this.potentiallyVulnerableLog4j1 = true;
	}

	public boolean isPotentiallyVulnerableLogback() {
		return potentiallyVulnerableLogback;
	}

	public void setPotentiallyVulnerableLogback() {
		this.potentiallyVulnerableLogback = true;
	}

	public boolean hasNestedJar() {
		return nestedJar;
	}

	public void setNestedJar(boolean nestedJar) {
		this.nestedJar |= nestedJar;
	}

	public Status getStatus() {
		if (vulnerable)
			return Status.VULNERABLE;
		else if (mitigated)
			return Status.MITIGATED;
		else if (isPotentiallyVulnerable())
			return Status.POTENTIALLY_VULNERABLE;
		return Status.NOT_VULNERABLE;
	}

	public boolean isPotentiallyVulnerable() {
		return potentiallyVulnerableLog4j2 || potentiallyVulnerableLog4j1 || potentiallyVulnerableLogback;
	}

	public boolean isFixRequired() {
		// Don't touch potentially vulnerable log4j2
		return vulnerable || potentiallyVulnerableLog4j1 || potentiallyVulnerableLogback;
	}
}
