class WorkflowGraph:

    def __init__(self):
        self.pages = {}
        self.transitions = []

    def register_page(self, url, dom_hash, depth):

        state_id = f"{url}:{dom_hash}"

        self.pages[state_id] = {
            "url": url,
            "depth": depth,
            "dom_hash": dom_hash
        }

        return state_id

    def calculate_priority(self, url):

        score = 0

        if "admin" in url:
            score += 50

        if "api" in url:
            score += 30

        if "upload" in url:
            score += 20

        return score