import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface VTAnalysisResult {
  engine_name: string;
  category: string;
  result: string;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const { url } = await req.json();
    if (!url) {
      return new Response(JSON.stringify({ error: "url is required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const apiKey = Deno.env.get("VIRUSTOTAL_API_KEY");
    if (!apiKey) {
      return new Response(JSON.stringify({ error: "VIRUSTOTAL_API_KEY not configured" }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const submitResp = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(url)}`,
    });

    let analysisId: string | null = null;
    if (submitResp.ok) {
      const submitData = await submitResp.json();
      analysisId = submitData?.data?.id ?? null;
    }

    const urlId = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    let analysisResults: VTAnalysisResult[] | null = null;
    let reputation: number | null = null;

    const urlResp = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": apiKey },
    });

    if (urlResp.ok) {
      const urlData = await urlResp.json();
      const attrs = urlData?.data?.attributes;
      if (attrs) {
        reputation = attrs.reputation ?? null;
        const analyses = attrs.last_analysis_results;
        if (analyses) {
          analysisResults = Object.entries(analyses).map(([engine, v]: [string, any]) => ({
            engine_name: engine, category: v.category || "harmless", result: v.result || "",
          }));
        }
      }
    }

    if (!analysisResults && analysisId) {
      for (let i = 0; i < 10; i++) {
        await new Promise((r) => setTimeout(r, 3000));
        const aResp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          headers: { "x-apikey": apiKey },
        });
        if (aResp.ok) {
          const aData = await aResp.json();
          if (aData?.data?.attributes?.status === "completed") {
            const results = aData?.data?.attributes?.results;
            if (results) {
              analysisResults = Object.entries(results).map(([engine, v]: [string, any]) => ({
                engine_name: engine, category: v.category || "harmless", result: v.result || "",
              }));
            }
            break;
          }
        }
      }
    }

    if (!analysisResults) {
      return new Response(JSON.stringify({
        url, malicious_count: 0, total_engines: 0, vendors: [], reputation,
        error: "Analysis not yet available — URL submitted, try again in a few seconds.",
      }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const vendors = analysisResults.map((r) => ({
      engine_name: r.engine_name, category: r.category, result: r.result,
      is_malicious: ["malicious", "suspicious", "phishing", "malware", "spam"].includes(r.category.toLowerCase()),
    }));

    const malicious_count = vendors.filter((v) => v.is_malicious).length;

    return new Response(JSON.stringify({
      url, malicious_count, total_engines: vendors.length, vendors, reputation,
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
