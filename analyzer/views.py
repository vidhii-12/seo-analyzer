# analyzer/views.py
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from .utils import crawl_site, keyword_check_logic
import json, csv, io

# Simple in-memory store for latest results (dev use only)
LAST_RUN_RESULTS = []

def home(request):
    global LAST_RUN_RESULTS
    if request.method == "POST":
        url = request.POST.get("url")
        mode = request.POST.get("mode", "single")
        full = (mode == "entire")
        # Run crawl (synchronous). For big crawls consider background job.
        results = crawl_site(url, full=full)
        LAST_RUN_RESULTS = results  # store copy to enable download
        return render(request, "analyzer/index.html", {"results": results})
    return render(request, "analyzer/index.html")

@csrf_exempt
def keyword_check(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            url = data.get("url")
            keyword = data.get("keyword")
            if not url or not keyword:
                return JsonResponse({"error": "Provide both URL and keyword"}, status=400)
            result = keyword_check_logic(url, keyword)
            return JsonResponse(result)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "POST method required"}, status=405)

def download_csv(request):
    """
    Download last run results as CSV. Simple: flatten a few fields for quick report.
    """
    global LAST_RUN_RESULTS
    if not LAST_RUN_RESULTS:
        return HttpResponse("No results yet. Run an analysis first.", status=400)

    output = io.StringIO()
    writer = csv.writer(output)
    # header
    writer.writerow(["url", "score", "title", "meta_description", "word_count", "internal_links", "external_links", "broken_links", "missing_image_alts", "has_jsonld", "has_sitemap"])
    for r in LAST_RUN_RESULTS:
        meta = r.get("meta", {})
        page_quality = r.get("page_quality", {})
        links = r.get("links", {})
        images = r.get("images", {})
        schema = r.get("schema", {})
        sitemap = r.get("sitemap", {})
        writer.writerow([
            r.get("url"),
            r.get("score"),
            meta.get("Title"),
            meta.get("Meta_Description"),
            page_quality.get("Word_Count"),
            links.get("Internal"),
            links.get("External"),
            links.get("Broken"),
            images.get("missing_alt"),
            schema.get("json_ld"),
            sitemap.get("found")
        ])

    resp = HttpResponse(output.getvalue(), content_type="text/csv")
    resp["Content-Disposition"] = 'attachment; filename="seo_results.csv"'
    return resp
