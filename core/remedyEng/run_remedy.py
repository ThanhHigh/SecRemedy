from core.remedyEng.remediator import Remediator

if __name__ == "__main__":
    # Tạo instance của Remediator
    remediator = Remediator()

    remediator.display_header()
    remediator.call_user_interact_TUI()