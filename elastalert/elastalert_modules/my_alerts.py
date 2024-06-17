from elastalert.alerters.email import EmailAlerter
from elastalert.alerts import BasicMatchString
from elastalert.util import lookup_es_key, pretty_ts


class CustomEmailAlter(EmailAlerter):
    def get_time_period(self, matches):
        lt = self.rules.get('use_local_time')
        fmt = self.rules.get('custom_pretty_ts_format')
        ts_field = self.rules.get('timestamp_field', '@timestamp')
        times = list()
        for match in matches:
            match_ts = lookup_es_key(match, ts_field)
            times.append(match_ts)
        
        start_time = pretty_ts(min(times), lt, fmt)
        end_time  = pretty_ts(max(times), lt, fmt)
        return start_time, end_time

    def create_alert_body(self, matches):
        body = ''
        start_time, end_time = self.get_time_period(matches)
        body += 'There are %d events occurred between %s and %s\n\n' % (len(matches),
                                                                         start_time,
                                                                         end_time)
        if self.rule.get('alert_text_type') != 'aggregation_summary_only':
            for match in matches:
                body += str(BasicMatchString(self.rule, match))
                # Separate text of aggregated alerts with dashes
                if len(matches) > 1:
                    body += '\n----------------------------------------\n'
        
        body += self.get_aggregation_summary_text(matches) # summary table
        
        return body
