''' Implements a file output / results processor for Kako. '''

import os
import time
import logging
import multiprocessing

import json


class Processor(multiprocessing.Process):
    ''' File output / results processor for Kako. '''

    def __init__(self, configuration, results, *args, **kwargs):
        super(Processor, self).__init__()

        self.log = logging.getLogger(__name__)
        self.results = results
        self.configuration = configuration
        self.output = os.path.join(
            self.configuration['results']['attributes']['path'],
            'kako.json'
        )
        self.ip_whilelist = self.configuration['alerts']['ip_whilelist']
        self.time_window = self.configuration['alerts']['time_window']
        self.max_count = self.configuration['alerts']['max_count']
        self.freq_count = {}

    def write(self, payload):
        ''' Implements a helper to write the provided payload to file. '''
        with open(self.output, 'a') as hndl:
            hndl.write(payload)
            hndl.write('\r\n')

    def alert(self, interaction):
        ''' sensitive action '''
        if interaction.sensitive:
            self.write('WARNING: ### %s attempts to get data ###' % interaction.source_ip)
            return

        ''' alert for ip outside the whitelist '''
        if interaction.source_ip not in self.ip_whilelist:
            self.write('WARNING: ### unknown IP address %s ###' % interaction.source_ip)
        
        ''' alert for frequent connections '''
        if interaction.source_ip not in self.freq_count.keys():
            self.freq_count[interaction.source_ip] = []
        self.freq_count[interaction.source_ip].append(int(time.time()))
        self.freq_count[interaction.source_ip][:] = [ts for ts in self.freq_count[interaction.source_ip] if int(time.time()) - ts < self.time_window]
        # self.write('count %d' % len(self.freq_count[interaction.source_ip]))
        if len(self.freq_count[interaction.source_ip]) > self.max_count:
            self.write('WARNING: ### possible DOS from %s ###' % interaction.source_ip)

    def run(self):
        ''' Implements the main runable for the processor. '''
        self.log.info('Setting up File results / output processor')
        while True:
            # When there is data in the queue, attempt to pull it and write to
            # the output file. If something goes awry, requeue the message
            # prior to throwing the exception.
            if self.results.qsize() > 0:
                self.log.info(
                    '%s interaction captures in the queue',
                    self.results.qsize()
                )
                interaction = self.results.get()
                self.log.debug('Attempting to write interaction to file')
                try:
                    self.write(interaction.toJSON())
                    self.alert(interaction)
                except (AttributeError, IOError, PermissionError):
                    self.log.error('Requeuing interaction, as write failed...')
                    self.results.put(interaction)
                    raise
                self.log.debug('Interaction written okay')
