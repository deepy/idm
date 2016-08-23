def baseurl(request):
    """
    Return a BASE_URL template context for the current request.
    """
    path = request.path.split("/")

    return {'BASE_URL': path[0] + '/' + path[1],}