export default async (request, context) => {
  const response = await context.next();
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('text/html')) return response;

  const token = Deno.env.get('AIRTABLE_TOKEN') || '';
  if (!token) return response;

  const html = await response.text();
  const injected = html.replace(
    '</head>',
    `<script>window.__AT__="${token}";</script></head>`
  );
  return new Response(injected, {
    status: response.status,
    headers: response.headers,
  });
};
