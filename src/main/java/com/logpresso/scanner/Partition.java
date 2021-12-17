package com.logpresso.scanner;

public class Partition {
	private String type;
	private String path;
	private String name;

	public Partition(String type, String path, String name) {
		this.type = type;
		this.path = path;
		this.name = name;
	}

	public String getType() {
		return type;
	}

	public String getPath() {
		return path;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return path + " (" + type + ")";
	}

}
