import logging

# Logging ##########################
log = logging.getLogger(__name__)
#log = logging.getLogger()
log.setLevel(logging.INFO)

# create a file handler
handler = logging.FileHandler("logs/log")
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
log.addHandler(handler)
#return log
####################################
