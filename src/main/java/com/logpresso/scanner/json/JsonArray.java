package com.logpresso.scanner.json;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

public class JsonArray {
	private final List<Object> objects = new ArrayList<Object>();

	public void add(Object obj) {
		if (obj != null) {
			objects.add(obj);
		}
	}

	public void write(Writer writer) throws IOException {
		write(writer, 0);
	}

	public void write(Writer writer, int depth) throws IOException {
		boolean comma = false;
		writer.write("[\n");

		for (Object obj : objects) {
			if (comma) {
				writer.write(",\n");
			}

			writeTab(writer, depth + 1);
			if (obj instanceof JsonObject) {
				((JsonObject) obj).write(writer, depth + 1);
			} else if (obj instanceof String) {
				writer.write(JsonObject.quote(obj.toString()));
			} else if (obj instanceof Number) {
				writer.write(obj.toString());
			}

			comma = true;
		}
		writer.write('\n');
		writeTab(writer, depth);
		writer.write(']');
	}

	private void writeTab(Writer writer, int depth) throws IOException {
		for (int i = 0; i < depth; i++)
			writer.write("    ");
	}
}
