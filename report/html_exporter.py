from jinja2 import Template

from scanner.detector import REQUIRED_HEADERS

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Header Report</title>
    <style>
        body { font-family: sans-serif; background: #f7f7f7; padding: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: center; }
        th { background: #333; color: #fff; }
        td.ok { background-color: #c8e6c9; }
        td.bad { background-color: #ffcdd2; }
        td.na { background-color: #eeeeee; color: #666; }
        .section { margin-top: 30px; }
        .note { margin: 5px 0; }
        .medium { color: #fbc02d; }
        .observation { color: #1e88e5; }
    </style>
</head>
<body>
    <h1>Security Header Report</h1>
    <table>
        <tr>
            <th>Header</th>
            <th>HTTPS/1.1</th>
            <th>HTTPS/1.0</th>
            <th>HTTP/1.1</th>
            <th>HTTP/1.0</th>
        </tr>
        {% for header in headers %}
        <tr>
            <td>{{ header }}</td>
            {% for scheme in ['HTTPS', 'HTTP'] %}
                {% for ver in ['1.1', '1.0'] %}
                    {% set result = results[scheme][ver] %}
                    {% if result %}
                        {% set is_required = header in REQUIRED_HEADERS.get(scheme, {}).get(ver, []) %}
                        {% set status = result.headers.get(header, False) %}
                        {% if is_required %}
                            <td class="{{ 'ok' if status else 'bad' }}">{{ '✓' if status else '✗' }}</td>
                        {% else %}
                            <td class="na"></td>
                        {% endif %}
                    {% else %}
                        <td class="na">N/A</td>
                    {% endif %}
                {% endfor %}
            {% endfor %}
        </tr>
        {% endfor %}
    </table>

    {% for scheme in ['HTTPS', 'HTTP'] %}
        {% for ver in ['1.1', '1.0'] %}
            {% set result = results[scheme][ver] %}
            {% if result and result.notes %}
                <div class="section">
                    <h2>{{ scheme }} {{ ver }} Notes</h2>
                    {% for note in result.notes %}
                        {% if 'Medium' in note %}
                            <div class="note medium">{{ note | safe }}</div>
                        {% elif 'Observation' in note %}
                            <div class="note observation">{{ note | safe }}</div>
                        {% else %}
                            <div class="note">{{ note | safe }}</div>
                        {% endif %}
                    {% endfor %}
                </div>
            {% endif %}
        {% endfor %}
    {% endfor %}
</body>
</html>
"""

def export_to_html(results, filename):
    headers = sorted({
        h
        for proto in results.values()
        for ver in proto.values()
        if ver
        for h in ver["headers"]
    })

    template = Template(HTML_TEMPLATE)
    rendered = template.render(results=results, headers=headers, REQUIRED_HEADERS=REQUIRED_HEADERS)

    with open(filename, "w") as f:
        f.write(rendered)
