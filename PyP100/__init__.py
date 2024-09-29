# from enum import IntEnum


# class MeasureInterval(IntEnum):
#     HOURS = 60
#     DAYS = 1440
#     MONTHS = 43200


class MeasureInterval:
    def __init__(self, value):
        self.value = value

MeasureInterval.HOURS = MeasureInterval(60)
MeasureInterval.DAYS = MeasureInterval(1440)
MeasureInterval.MONTHS = MeasureInterval(43200)
