from datetime import datetime, timedelta, date

from AnyQt.QtCore import QDate
from AnyQt.QtWidgets import QDateEdit, QComboBox, QFormLayout

from orangewidget.utils.widgetpreview import WidgetPreview

from Orange.widgets import widget, gui, settings
from Orange.widgets.widget import Output

from orangecontrib.timeseries import Timeseries
# 2026-05-28: yfinance 1.4.0 에서 pdr_override() 제거 → finance_data() 가
# AttributeError 로 실패. 자체 _finance_data() 로 대체 (yf.Ticker.history 사용).
from Orange.data import Domain
from Orange.data.pandas_compat import table_from_frame
import yfinance as _yf

def _finance_data(symbol, since=None, until=None):
    """yfinance 최신 API 로 주가 데이터 조회 — 기존 finance_data() 대체."""
    if since is None:
        since = date(1900, 1, 1)
    if until is None:
        until = date.today()
    ticker = _yf.Ticker(symbol)
    # end 는 exclusive 라서 1일 추가
    df = ticker.history(
        start=since.strftime('%Y-%m-%d'),
        end=(until + timedelta(days=1)).strftime('%Y-%m-%d'),
        auto_adjust=False,
    )
    if df.empty:
        raise ValueError(f"No data for symbol: {symbol}")
    # tz 제거 + Date 컬럼화 (기존 finance_data 와 동일 구조).
    # yfinance 는 tz-aware datetime 반환 → Orange3 Timeseries 는 naive 기대.
    df = df.reset_index()
    if 'Date' in df.columns:
        try:
            df['Date'] = df['Date'].dt.tz_convert(None)
        except (TypeError, AttributeError):
            pass
        try:
            df['Date'] = df['Date'].dt.tz_localize(None)
        except (TypeError, AttributeError):
            pass
    # 'Adj Close' 컬럼이 없으면 'Close' 로 대체 (auto_adjust=False 에서는 보통 존재)
    if 'Adj Close' not in df.columns and 'Close' in df.columns:
        df['Adj Close'] = df['Close']
    data = Timeseries.from_data_table(table_from_frame(df))
    # Adj Close 를 class 변수로 이동 (기존 finance_data 동작 유지)
    attrs = [v.name for v in data.domain.attributes]
    if 'Adj Close' in attrs:
        attrs.remove('Adj Close')
        data = data.transform(
            Domain(attrs, [data.domain['Adj Close']], source=data.domain))
    data.name = symbol
    data.time_variable = data.domain['Date']
    return data


# 기존 호출 호환 — 위젯 코드는 finance_data 만 사용.
finance_data = _finance_data


class OWYahooFinance(widget.OWWidget):
    name = 'Yahoo Finance'
    description = "Generate time series from Yahoo Finance stock market data."
    icon = 'icons/YahooFinance.svg'
    priority = 9

    class Outputs:
        time_series = Output("Time series", Timeseries)

    QT_DATE_FORMAT = 'yyyy-MM-dd'
    PY_DATE_FORMAT = '%Y-%m-%d'
    MIN_DATE = date(1851, 1, 1)

    date_from = settings.Setting(
        (datetime.now().date() - timedelta(5 * 365)).strftime(PY_DATE_FORMAT))
    date_to = settings.Setting(datetime.now().date().strftime(PY_DATE_FORMAT))
    symbols = settings.Setting(
        ['AMZN', 'AAPL', 'GOOG', 'FB', 'SPY', '^DJI', '^TNX'])

    want_main_area = False
    resizing_enabled = False

    class Error(widget.OWWidget.Error):
        download_error = widget.Msg('Failed to download data.\n'
                                    'No internet? Wrong stock symbol?')

    def __init__(self):
        layout = QFormLayout()
        gui.widgetBox(self.controlArea, True, orientation=layout)

        self.combo = combo = QComboBox(
            editable=True, insertPolicy=QComboBox.InsertAtTop)
        combo.addItems(self.symbols)
        layout.addRow("Ticker:", self.combo)
        minDate = QDate.fromString(self.MIN_DATE.strftime(self.PY_DATE_FORMAT),
                                   self.QT_DATE_FORMAT)
        date_from, date_to = (
            QDateEdit(QDate.fromString(date, self.QT_DATE_FORMAT),
                      displayFormat=self.QT_DATE_FORMAT, minimumDate=minDate,
                      calendarPopup=True)
            for date in (self.date_from, self.date_to))

        @date_from.dateChanged.connect
        def set_date_from(date):
            self.date_from = date.toString(self.QT_DATE_FORMAT)

        @date_to.dateChanged.connect
        def set_date_to(date):
            self.date_to = date.toString(self.QT_DATE_FORMAT)

        layout.addRow("From:", date_from)
        layout.addRow("To:", date_to)

        self.button = gui.button(
            self.controlArea, self, 'Download', callback=self.download)

    def download(self):
        date_from = datetime.strptime(self.date_from, self.PY_DATE_FORMAT)
        date_to = datetime.strptime(self.date_to, self.PY_DATE_FORMAT)

        # Update symbol in symbols history
        symbol = self.combo.currentText().strip().upper()
        self.combo.removeItem(self.combo.currentIndex())
        self.combo.insertItem(0, symbol)
        self.combo.setCurrentIndex(0)
        try:
            self.symbols.remove(symbol)
        except ValueError:
            pass
        self.symbols.insert(0, symbol)

        if not symbol:
            return

        self.Error.clear()
        with self.progressBar(3) as progress:
            try:
                progress.advance()
                self.button.setDisabled(True)
                data = finance_data(symbol, date_from, date_to)

                self.Outputs.time_series.send(data)
            except Exception as e:
                self.Error.download_error()
            finally:
                self.button.setDisabled(False)


if __name__ == "__main__":
    WidgetPreview(OWYahooFinance).run()
